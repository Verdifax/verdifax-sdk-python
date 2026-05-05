# Releasing the Verdifax Python SDK

This document covers the manual publish path. CI runs the same steps automatically when a `v*` git tag is pushed (see `.github/workflows/release.yml`).

## Prerequisites

- Python 3.11+
- A PyPI account with an API token (`pypi-...`) saved in `~/.pypirc`, or a TestPyPI token for the dry-run step
- Push access to the GitHub repository

## 1. Bump the version

Update `__version__` in `verdifax/_version.py` and the `version` field in `pyproject.toml` and `setup.cfg`. They must match.

## 2. Run the test suite

```bash
pip install -r requirements-dev.txt
pip install -e .
pytest -v
mypy verdifax
black --check verdifax tests
```

## 3. Build the wheel and sdist

```bash
rm -rf dist build *.egg-info
python -m build
```

This produces:

- `dist/verdifax-X.Y.Z-py3-none-any.whl`
- `dist/verdifax-X.Y.Z.tar.gz`

Validate them:

```bash
twine check dist/*
```

## 4. Verify install in a clean virtualenv

```bash
python -m venv /tmp/verdifax-verify
/tmp/verdifax-verify/bin/pip install dist/verdifax-*.whl
/tmp/verdifax-verify/bin/python -c "import verdifax; print(verdifax.__version__)"
```

## 5. Publish to TestPyPI (dry run)

```bash
twine upload --repository testpypi dist/*
```

Then verify the install works from there:

```bash
pip install --index-url https://test.pypi.org/simple/ \
            --extra-index-url https://pypi.org/simple/ \
            verdifax
```

## 6. Publish to PyPI

```bash
twine upload dist/*
```

## 7. Tag the release

```bash
git tag -a v0.1.0 -m "Release 0.1.0"
git push origin v0.1.0
```

The `release.yml` workflow will additionally publish from CI when the tag arrives, but it is idempotent — PyPI rejects duplicate uploads, so if you already pushed manually the CI run will safely no-op on the upload step.

## 8. Smoke-test the published package

```bash
python -m venv /tmp/verdifax-pypi
/tmp/verdifax-pypi/bin/pip install verdifax
/tmp/verdifax-pypi/bin/python -c "import verdifax; print(verdifax.__version__)"
```
