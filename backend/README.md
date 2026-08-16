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
uv run playwright install chromium
```

This installs both runtime and dev dependency groups (pytest, ruff) into `.venv`, plus the
Chromium binary required for browser-validated XSS scans. The backend Docker image performs
the browser installation automatically.

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
uv run python scripts/manual_check_xss.py --base-url http://localhost:8081
uv run python scripts/manual_check_path_traversal.py --base-url http://localhost:8080
```

`vulnerable_services` needs `nmap` and `searchsploit` on PATH (both already in the
backend Docker image; install locally too if running outside Docker — see the
Dockerfile for the exploitdb clone `searchsploit` needs) and takes longer since it's a
real port scan plus a per-service NVD lookup:

```bash
docker compose -f lab/docker-compose.yml up -d metasploitable2
cd backend
uv run python scripts/manual_check_vulnerable_services.py metasploitable2
uv run python scripts/manual_check_vulnerable_services.py --ports 1-1000 metasploitable2
```

CVE matching for this detector comes from two layers: a small curated table for
lab-only backdoors NVD has no CVE for (vsftpd/ProFTPD/UnrealIRCd source-compromise
backdoors, the ingreslock listener) plus insecure-by-design protocols (telnet,
rsh/rlogin/rexec, unauthenticated VNC); and the NVD CVE API, queried by CPE, for
everything else — which is what makes it work against services beyond the lab's known
list. NVD lookups work unauthenticated (5 req/30s) but go faster with a free key from
<https://nvd.nist.gov/developers/request-an-api-key> set as `NVD_API_KEY` in `.env`.

`weak_tls` needs a TLS-speaking target — the lab's `tls-test` container (a
deliberately weak nginx build) or any other host:

```bash
docker compose -f lab/docker-compose.yml up -d --build tls-test
cd backend
uv run python scripts/manual_check_weak_tls.py tls-test
uv run python scripts/manual_check_weak_tls.py --port 8443 localhost
```

Unlike the other detectors, `weak_tls` doesn't shell out to anything — it uses
[SSLyze](https://github.com/nabla-c0d3/sslyze) as a Python library (`sslyze` in
`pyproject.toml`), which runs every scan command by default: protocol/cipher
enumeration for SSL 2.0 through TLS 1.3, certificate chain validation, and read-only
probes for Heartbleed/ROBOT/CCS-injection/insecure-renegotiation.

This prints the detector's verdict, severity, confidence, CWE/CVSS, and the exact
evidence collected (e.g. which files were confirmed exposed) — useful for confirming a
new or changed detector behaves correctly against the real target before relying on
unit tests alone. Add a new `manual_check_<detector>.py` script following the same
pattern when adding a detector.
