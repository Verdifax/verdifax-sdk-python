"""The signal feed, feed keys, webhooks and failure receipts, shared by both clients.

The feed lists every control signal Verdifax recorded for an account, in
order: a run refused, halted or failed, a policy changed, a sign-off
recorded, an approver key registered or revoked, a key created or revoked.
Each event is a CloudEvent carrying its place in the account's feed, the
hash of the event before it, its own hash and the sealed entry it names. The
feed cannot show a signal Verdifax never recorded.

A feed key reads the feed, ``GET /signals``, and nothing else. The owner key
reads the same feed at ``GET /account/signals``. A webhook delivery is a
copy of one event, signed under the Standard Webhooks scheme; the pull feed
and the public log are the record. This module makes no request itself: it
checks arguments, builds paths and bodies, reads pages, and checks webhook
deliveries.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import (
    Any,
    AsyncGenerator,
    Awaitable,
    Callable,
    Generator,
    Iterable,
    Mapping,
    Optional,
    Union,
)

from ._requests import account_key_body
from ._signoffs import _text
from ._validation import validate_positive_id
from .exceptions import ValidationError, VerdifaxError, WebhookVerificationError

SIGNAL_FORM = "verdifax.signal.v1"
SIGNAL_TYPE_PREFIX = "com.verdifax."
SIGNAL_KINDS = (
    "run.refused",
    "run.halted",
    "run.failed",
    "policy.changed",
    "signoff.recorded",
    "approver.registered",
    "approver.revoked",
    "key.created",
    "key.revoked",
    "run.published",
    "run.unpublished",
)
SIGNALS_PATH = "/signals"
ACCOUNT_SIGNALS_PATH = "/account/signals"
FEED_KEYS_PATH = "/account/feed-keys"
WEBHOOKS_PATH = "/account/webhooks"
SIGNAL_PAGE_MAX = 500
SIGNAL_WAIT_MAX = 25
FOLLOW_WAIT_DEFAULT = 25
# The HTTP timeout of a feed read is at least its wait plus this margin.
SIGNAL_TIMEOUT_MARGIN = 30
# With wait=0 the server answers an empty page at once, so follow_signals
# pauses this long before it asks again rather than polling without a break.
FOLLOW_IDLE_PAUSE = 1.0
DELIVERY_PAGE_MAX = 500
WEBHOOK_SECRET_PREFIX = "whsec_"
WEBHOOK_SIGNATURE_VERSION = "v1"
DEFAULT_WEBHOOK_TOLERANCE = 300
_WEBHOOK_HEADERS = ("webhook-id", "webhook-timestamp", "webhook-signature")


def _whole_number(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{field_name} must be an int, got {type(value).__name__}")
    result: int = value
    return result


def _in_range(value: Any, field_name: str, low: int, high: int, unit: str = "") -> int:
    number = _whole_number(value, field_name)
    if not low <= number <= high:
        raise ValidationError(f"{field_name} must be {low} to {high}{unit}, got {number}")
    return number


def _owner_flag(as_owner: Any) -> bool:
    if not isinstance(as_owner, bool):
        raise ValidationError(f"as_owner must be a bool, got {type(as_owner).__name__}")
    return as_owner


def signals_path(as_owner: Any = False) -> str:
    """``/account/signals`` for the owner key, else ``/signals`` for a feed key."""
    return ACCOUNT_SIGNALS_PATH if _owner_flag(as_owner) else SIGNALS_PATH


def signals_timeout(client_timeout: Any, wait: int) -> Optional[float]:
    """The HTTP timeout of a feed read: the client's, or the wait plus 30 seconds if longer.

    A client with no timeout (``None``) keeps none.
    """
    if client_timeout is None:
        return None
    floor = float(wait + SIGNAL_TIMEOUT_MARGIN)
    if isinstance(client_timeout, (int, float)) and not isinstance(client_timeout, bool):
        return max(float(client_timeout), floor)
    return floor


@dataclass(frozen=True)
class SignalsRequest:
    """One checked feed read: its route, query and HTTP timeout."""

    path: str
    params: dict[str, int]
    timeout: Optional[float]
    after: int
    wait: int


def signals_request(
    after: Any = 0,
    limit: Any = None,
    wait: Any = 0,
    as_owner: Any = False,
    client_timeout: Any = None,
) -> SignalsRequest:
    """Check the arguments of a feed read and build its request.

    The query always carries ``after`` and ``wait``, and ``limit`` only when
    given, so the server applies its default of 100.

    Raises:
        ValidationError: If ``after`` is not a whole number of 0 or more,
            ``limit`` is not 1 to 500, ``wait`` is not 0 to 25 seconds, or
            ``as_owner`` is not a bool.
    """
    place = _whole_number(after, "after")
    if place < 0:
        raise ValidationError(f"after must be 0 or more, the last sequence read, got {place}")
    seconds = _in_range(wait, "wait", 0, SIGNAL_WAIT_MAX, " seconds")
    params: dict[str, int] = {"after": place}
    if limit is not None:
        params["limit"] = _in_range(limit, "limit", 1, SIGNAL_PAGE_MAX)
    params["wait"] = seconds
    path = signals_path(as_owner)
    return SignalsRequest(path, params, signals_timeout(client_timeout, seconds), place, seconds)


def follow_request(after: Any = 0, wait: Any = FOLLOW_WAIT_DEFAULT, as_owner: Any = False) -> None:
    """Check the arguments of ``follow_signals`` before anything is sent.

    Raises:
        ValidationError: As :func:`signals_request` does.
    """
    signals_request(after, None, wait, as_owner)


def signal_page(body: Any, source: str) -> dict[str, Any]:
    """Read one page of the feed, as the server sent it.

    Raises:
        VerdifaxError: If the page has no ``events`` list, or ``next_after``
            or ``newest`` is not a whole number.
    """
    if not isinstance(body, dict):
        raise VerdifaxError(f"{source} did not return an object")
    if not isinstance(body.get("events"), list):
        raise VerdifaxError(f"{source} returned no events list")
    for name in ("next_after", "newest"):
        value = body.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise VerdifaxError(f"{source} returned no usable {name}")
    return body


def _event_sequence(event: Any) -> Optional[int]:
    data = event.get("data") if isinstance(event, Mapping) else None
    sequence = data.get("sequence") if isinstance(data, Mapping) else None
    if isinstance(sequence, bool) or not isinstance(sequence, int):
        return None
    return sequence


def next_place(page: Mapping[str, Any], after: int, source: str) -> int:
    """The place to read from next, after checking the page skips and repeats nothing.

    Every event's sequence is after ``after`` and after the one before it,
    and ``next_after`` is the last event's sequence, or ``after`` itself
    when the page is empty.

    Raises:
        VerdifaxError: If the page would skip or repeat an event.
    """
    place = after
    for event in page["events"]:
        sequence = _event_sequence(event)
        if sequence is None:
            raise VerdifaxError(f"{source} returned an event with no data.sequence")
        if sequence <= place:
            raise VerdifaxError(
                f"{source} returned event {sequence} after {place}: the feed went backwards"
            )
        place = sequence
    if page["next_after"] != place:
        raise VerdifaxError(
            f"{source} returned next_after {page['next_after']} where the page ends at "
            f"{place}: following it would skip or repeat events"
        )
    return place


def with_place(exc: VerdifaxError, after: int) -> VerdifaxError:
    """Mark an error from ``follow_signals`` with the last sequence read."""
    exc.last_sequence = after
    return exc


def follow(
    read_page: Callable[[int], dict[str, Any]],
    after: int,
    wait: int,
    source: str,
    sleep: Optional[Callable[[float], None]] = None,
) -> Generator[dict[str, Any], None, None]:
    """Read page after page from ``after``, yielding each event, until the caller stops.

    ``read_page(after)`` reads one page with the client's own retry policy.
    An error it raises, or a page that would skip or repeat an event, is
    raised with ``last_sequence`` set to the last sequence read. After an
    empty page read with ``wait=0`` it pauses one second before the next.
    """
    place = after
    while True:
        try:
            page = read_page(place)
            events = list(page["events"])
            following = next_place(page, place, source)
        except VerdifaxError as exc:
            raise with_place(exc, place)
        for event in events:
            yield event
        place = following
        if not events and wait == 0:
            (sleep or time.sleep)(FOLLOW_IDLE_PAUSE)


async def follow_async(
    read_page: Callable[[int], Awaitable[dict[str, Any]]],
    after: int,
    wait: int,
    source: str,
    sleep: Optional[Callable[[float], Awaitable[None]]] = None,
) -> AsyncGenerator[dict[str, Any], None]:
    """The async form of :func:`follow`."""
    place = after
    while True:
        try:
            page = await read_page(place)
            events = list(page["events"])
            following = next_place(page, place, source)
        except VerdifaxError as exc:
            raise with_place(exc, place)
        for event in events:
            yield event
        place = following
        if not events and wait == 0:
            await (sleep or asyncio.sleep)(FOLLOW_IDLE_PAUSE)


def feed_key_body(name: Any, expires_at: Any = None) -> dict[str, str]:
    """The body of ``POST /account/feed-keys``: the name and an optional RFC 3339 cutoff.

    Raises:
        ValidationError: If ``name`` is empty, or ``expires_at`` is not a ``str``.
    """
    return account_key_body(name, expires_at)


def feed_key_path(id: Any) -> str:
    """Validate ``id`` and build ``/account/feed-keys/{id}``."""
    validate_positive_id(id, "id")
    return f"{FEED_KEYS_PATH}/{id}"


def webhook_body(url: Any, types: Any = None) -> dict[str, Any]:
    """The body of ``POST /account/webhooks``.

    ``types`` is a list of signal kinds, each at most once; ``None`` or an
    empty list takes every kind. The server checks the address too; this
    refusal is only the first check.

    Raises:
        ValidationError: If ``url`` is not a string starting ``https://``, or
            ``types`` is not a list of distinct signal kinds.
    """
    if not isinstance(url, str) or not url.startswith("https://") or len(url) <= len("https://"):
        raise ValidationError("url must be a string starting https://")
    if types is None:
        kinds: list[str] = []
    elif isinstance(types, (list, tuple)):
        kinds = []
        for kind in types:
            if kind not in SIGNAL_KINDS:
                raise ValidationError(
                    f"types must be signal kinds ({', '.join(SIGNAL_KINDS)}), got {kind!r}"
                )
            if kind in kinds:
                raise ValidationError(f"types names {kind} twice")
            kinds.append(kind)
    else:
        raise ValidationError(f"types must be a list of signal kinds, got {type(types).__name__}")
    return {"url": url, "types": kinds}


def webhook_path(id: Any, suffix: str = "") -> str:
    """Validate ``id`` and build ``/account/webhooks/{id}`` with an optional suffix."""
    validate_positive_id(id, "id")
    return f"{WEBHOOKS_PATH}/{id}{suffix}"


def deliveries_request(id: Any, limit: Any = None) -> tuple[str, dict[str, int]]:
    """Check a delivery-log read and build its path and query.

    Raises:
        ValidationError: If ``id`` is not a positive integer, or ``limit`` is
            not 1 to 500.
    """
    path = webhook_path(id, "/deliveries")
    params: dict[str, int] = {}
    if limit is not None:
        params["limit"] = _in_range(limit, "limit", 1, DELIVERY_PAGE_MAX)
    return path, params


def failure_receipt_path(run_id: Any) -> str:
    """Validate ``run_id`` and build ``/runs/{run_id}/failure-receipt``."""
    validate_positive_id(run_id, "run_id")
    return f"/runs/{run_id}/failure-receipt"


def signal_event_hash(
    kind: str, entry_hash: str, account: str, sequence: int, previous_signal_hash: str
) -> str:
    """The hash an event in the feed carries as ``data.event_hash``.

    It is the hex SHA-256 of ``verdifax.signal.v1``, ``kind``, ``entry_hash``,
    ``account``, the decimal ``sequence`` and ``previous_signal_hash``,
    joined by single zero bytes. Matches the orchestrator's
    ``SignalEventHash``. Makes no request.

    Raises:
        ValidationError: If a value is not text or holds a zero byte, which
            would make the joined bytes ambiguous, or ``sequence`` is not a
            whole number of 0 or more.
    """
    number = _whole_number(sequence, "sequence")
    if number < 0:
        raise ValidationError(f"sequence must be 0 or more, got {number}")
    values = (
        SIGNAL_FORM,
        _text(kind, "kind"),
        _text(entry_hash, "entry_hash"),
        _text(account, "account"),
        str(number),
        _text(previous_signal_hash, "previous_signal_hash"),
    )
    return hashlib.sha256("\x00".join(values).encode("utf-8")).hexdigest()


def _header_map(headers: Any) -> dict[str, str]:
    """The headers by lowercase name. A name given twice with two values is refused."""
    if isinstance(headers, Mapping):
        pairs: Iterable[Any] = headers.items()
    elif isinstance(headers, (list, tuple)):
        pairs = headers
    else:
        raise ValidationError(
            f"headers must be a mapping or a list of pairs, got {type(headers).__name__}"
        )
    found: dict[str, str] = {}
    for pair in pairs:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise ValidationError("headers must be a mapping or a list of (name, value) pairs")
        name, value = pair
        if isinstance(name, bytes):
            name = name.decode("latin-1")
        if isinstance(value, bytes):
            value = value.decode("latin-1")
        if not isinstance(name, str) or not isinstance(value, str):
            raise ValidationError("headers must hold text names and values")
        lower = name.lower()
        if lower in _WEBHOOK_HEADERS and lower in found and found[lower] != value:
            raise WebhookVerificationError(lower, "the header appears twice with two values")
        found[lower] = value
    return found


def _webhook_key(secret: Any) -> bytes:
    if not isinstance(secret, str) or not secret.startswith(WEBHOOK_SECRET_PREFIX):
        raise WebhookVerificationError("secret", "the secret must start with whsec_")
    try:
        key = base64.b64decode(secret[len(WEBHOOK_SECRET_PREFIX) :], validate=True)
    except (binascii.Error, ValueError):
        raise WebhookVerificationError("secret", "the text after whsec_ is not base64") from None
    if not key:
        raise WebhookVerificationError("secret", "the secret holds no key bytes")
    return key


def _body_bytes(body: Any) -> bytes:
    if isinstance(body, str):
        return body.encode("utf-8")
    if isinstance(body, (bytes, bytearray, memoryview)):
        return bytes(body)
    raise ValidationError(
        f"body must be the raw bytes received, or their text, got {type(body).__name__}"
    )


def _now_seconds(now: Any) -> float:
    if now is None:
        return time.time()
    if isinstance(now, datetime):
        moment = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
        return moment.timestamp()
    if isinstance(now, (int, float)) and not isinstance(now, bool):
        return float(now)
    raise ValidationError(f"now must be a datetime or seconds since 1970, got {type(now).__name__}")


def _tolerance(tolerance_seconds: Any) -> float:
    if isinstance(tolerance_seconds, bool) or not isinstance(tolerance_seconds, (int, float)):
        raise ValidationError(
            f"tolerance_seconds must be a number, got {type(tolerance_seconds).__name__}"
        )
    if tolerance_seconds < 0:
        raise ValidationError(f"tolerance_seconds must be 0 or more, got {tolerance_seconds}")
    return float(tolerance_seconds)


def verify_webhook(
    headers: Union[Mapping[str, str], Iterable[tuple[str, str]]],
    body: Union[bytes, bytearray, memoryview, str],
    secret: str,
    tolerance_seconds: float = DEFAULT_WEBHOOK_TOLERANCE,
    now: Optional[Union[datetime, float]] = None,
) -> dict[str, Any]:
    """Check a webhook delivery under the Standard Webhooks scheme and return its event.

    The signed content is ``webhook-id``, a dot, ``webhook-timestamp``, a
    dot and the raw body bytes, under HMAC-SHA256 with the key the
    ``whsec_`` secret holds. ``webhook-signature`` is a space-separated list
    of ``v1,<base64>`` entries, and any one of them may match; each is
    compared in constant time. Header names are read in any case. Makes no
    request, and never logs or returns the secret.

    A delivery is a copy of one event in the account's feed. The pull feed
    and the public log are the record.

    Args:
        headers: The delivery's headers, a mapping or a list of pairs.
        body: The raw body bytes received, before any JSON parsing, or
            their exact text.
        secret: The webhook's secret, ``whsec_`` and base64, as
            ``create_webhook`` returned it once.
        tolerance_seconds: How far ``webhook-timestamp`` may be from now,
            in either direction. Defaults to 300.
        now: The time to check against, a ``datetime`` or seconds since
            1970. Defaults to the current time.

    Returns:
        The CloudEvent the body holds.

    Raises:
        WebhookVerificationError: Naming the check that failed: the secret,
            a missing or doubled header, a timestamp that is not a whole
            number or is too far from now, no matching ``v1`` signature, a
            body that is not a JSON object, or a body whose top-level
            ``id`` is not a string equal to ``webhook-id``.
        ValidationError: If an argument has the wrong type.
    """
    raw = _body_bytes(body)
    window = _tolerance(tolerance_seconds)
    current = _now_seconds(now)
    key = _webhook_key(secret)
    found = _header_map(headers)
    for name in _WEBHOOK_HEADERS:
        if not found.get(name):
            raise WebhookVerificationError(name, "the header is missing")
    message_id = found["webhook-id"]
    stamp = found["webhook-timestamp"]
    if not stamp.isascii() or not stamp.isdigit():
        raise WebhookVerificationError(
            "webhook-timestamp", "the timestamp is not a whole number of seconds"
        )
    if abs(current - int(stamp)) > window:
        raise WebhookVerificationError(
            "webhook-timestamp",
            f"the timestamp is more than {window:g} seconds from now",
        )
    signed = message_id.encode("utf-8") + b"." + stamp.encode("ascii") + b"." + raw
    expected = hmac.new(key, signed, hashlib.sha256).digest()
    matched = False
    for entry in found["webhook-signature"].split(" "):
        version, _, encoded = entry.partition(",")
        if version != WEBHOOK_SIGNATURE_VERSION or not encoded:
            continue
        try:
            candidate = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            continue
        if hmac.compare_digest(expected, candidate):
            matched = True
    if not matched:
        raise WebhookVerificationError(
            "webhook-signature", "no v1 signature matches the id, timestamp and body"
        )
    try:
        event = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise WebhookVerificationError("body", "the body is not JSON") from None
    if not isinstance(event, dict):
        raise WebhookVerificationError("body", "the body is not a JSON object")
    # The signature covers webhook-id and the body separately, so a body
    # whose own id differs from the header is refused here.
    event_id = event.get("id")
    if not isinstance(event_id, str) or event_id != message_id:
        raise WebhookVerificationError("body", "the event id in the body does not match webhook-id")
    return event


__all__ = [
    "ACCOUNT_SIGNALS_PATH",
    "DEFAULT_WEBHOOK_TOLERANCE",
    "FEED_KEYS_PATH",
    "FOLLOW_IDLE_PAUSE",
    "FOLLOW_WAIT_DEFAULT",
    "SIGNALS_PATH",
    "SIGNAL_FORM",
    "SIGNAL_KINDS",
    "SIGNAL_PAGE_MAX",
    "SIGNAL_TIMEOUT_MARGIN",
    "SIGNAL_TYPE_PREFIX",
    "SIGNAL_WAIT_MAX",
    "SignalsRequest",
    "WEBHOOKS_PATH",
    "WEBHOOK_SECRET_PREFIX",
    "WebhookVerificationError",
    "deliveries_request",
    "failure_receipt_path",
    "feed_key_body",
    "feed_key_path",
    "follow",
    "follow_async",
    "follow_request",
    "next_place",
    "signal_event_hash",
    "signal_page",
    "signals_path",
    "signals_request",
    "signals_timeout",
    "verify_webhook",
    "webhook_body",
    "webhook_path",
    "with_place",
]
