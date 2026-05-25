# Verdifax, PyPI Trusted Publisher setup (one-time)

The release workflow at `.github/workflows/release.yml` already
uses PyPA's `gh-action-pypi-publish` with OIDC trusted publishing.
That means **no long-lived PyPI API token is stored anywhere**, the
GitHub Actions OIDC token authenticates directly with PyPI per
release.

This document covers the one-time setup needed before the first
release. After that, every `v*` tag push auto-publishes to PyPI.

---

## 1. Reserve the package name on PyPI

If `verdifax` is not yet on PyPI:

1. Sign in at https://pypi.org/account/login/
2. Visit https://pypi.org/manage/publishing/
3. Click **Add a new pending publisher** under "Add a new pending publisher"
4. Fill in:
   - **PyPI Project Name:** `verdifax`
   - **Owner:** `Verdifax`
   - **Repository name:** `verdifax-sdk-python`
   - **Workflow name:** `release.yml`
   - **Environment name:** `pypi`
5. Click **Add**.

The pending-publisher entry reserves the package name AND tells PyPI
which GitHub repo + workflow + environment is allowed to publish.
Until the first release lands, the package shows as "pending."

---

## 2. Configure the matching environment in GitHub

GitHub Actions environments are per-repo settings:

1. Open https://github.com/Verdifax/verdifax-sdk-python/settings/environments
2. Click **New environment**
3. Name: `pypi`
4. Click **Configure environment**
5. (Optional but recommended) Add **Required reviewers** = your
   GitHub username. This means every release tag triggers an
   approval prompt before the publish step runs, useful for
   catching accidental tag pushes.
6. Save.

---

## 3. Cut the first release

```bash
cd ~/VERDIFAX/verdifax-sdk-python

# Bump version
$EDITOR verdifax/_version.py     # set __version__ = "0.1.0-alpha.1"
$EDITOR pyproject.toml            # match the version in [project]
$EDITOR setup.cfg                 # match the version in [metadata]

# Commit + push
git add -A
git commit -m "Release v0.1.0-alpha.1"
git push origin main

# Tag + push the tag
git tag -a v0.1.0-alpha.1 -m "Verdifax SDK v0.1.0-alpha.1"
git push origin v0.1.0-alpha.1
```

The tag push triggers `.github/workflows/release.yml`. ~3 minutes
later the package lands at https://pypi.org/project/verdifax/.

---

## 4. Smoke-test the install

```bash
python -m venv /tmp/verdifax-pypi-smoke
/tmp/verdifax-pypi-smoke/bin/pip install verdifax==0.1.0-alpha.1
/tmp/verdifax-pypi-smoke/bin/python -c "import verdifax; print(verdifax.__version__)"
```

If that prints the version, the release is shipped end-to-end. The
`pip install verdifax` story is now true and buyer-pageable.

---

## What this DOESN'T do (intentionally)

- **It doesn't handle TestPyPI dry runs.** The manual path in
  `RELEASING.md` covers that. For automated releases, we trust the
  test suite + the trusted-publisher reviewer gate.
- **It doesn't cosign-sign the wheel.** PyPI doesn't yet enforce
  Sigstore signatures; we'll add this once PyPI's
  `pypi-attestations` flow ships. Tracked separately.
- **It doesn't update Homebrew or conda-forge.** Out of scope until
  the SDK has real production users asking for those distribution
  channels.
