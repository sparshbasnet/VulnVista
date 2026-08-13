# VulnVista backend

FastAPI service: target/scan/finding management plus the Python detector engine under
[app/scanners/](app/scanners/). See the repo-root [README](../README.md) and
[VulnVista_IMPLEMENTATION_PLAN.md](../VulnVista_IMPLEMENTATION_PLAN.md) for the full
architecture and roadmap.

## Setup

Dependencies are managed with [uv](https://docs.astral.sh/uv/):

```bash
cd backend
uv sync
```

This installs both runtime and dev dependency groups (pytest, ruff) into `.venv`.

## Running tests

```bash
uv run pytest
```

Detector tests (`tests/test_*.py`) import each detector's pure `classify()` /
`is_exposed()`-style decision functions directly and unit-test them with plain
`assert` — no network calls, no live lab required.

## Linting

```bash
uv run ruff check .
```

## Manual detector scripts

The automated test suite only covers each detector's pure decision logic, never the
live `check()` flow (the part that actually makes HTTP requests against a target). To
sanity-check a detector end-to-end against a real lab target, use the manual scripts
under [scripts/](scripts/):

```bash
# 1. Bring up the target lab (from the repo root), e.g. Juice Shop:
docker compose -f lab/docker-compose.yml up -d juice-shop

# 2. Run the detector against it and inspect the DetectorResult it produces:
cd backend
uv run python scripts/manual_check_sensitive_files.py
uv run python scripts/manual_check_sensitive_files.py --base-url http://localhost:3000
```

This prints the detector's verdict, severity, confidence, CWE/CVSS, and the exact
evidence collected (e.g. which files were confirmed exposed) — useful for confirming a
new or changed detector behaves correctly against the real target before relying on
unit tests alone. Add a new `manual_check_<detector>.py` script following the same
pattern when adding a detector.
