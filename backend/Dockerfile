FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1

# nmap: port discovery + service/version fingerprinting for the
# vulnerable_services detector (app/scanners/vulnerable_services.py). Run
# unprivileged (TCP connect scan, not SYN scan) so no extra capabilities are
# needed on the container.
#
# searchsploit: exploit-availability lookups for CVEs that detector finds via
# NVD. Not a Debian package (it's Kali-maintained) — the officially
# documented non-Kali install is cloning exploitdb directly and symlinking
# its own searchsploit script onto PATH. Adds ~230MB; there's no smaller
# offline option that still has the full CVE/EDB-ID cross-reference data.
# github.com/offensive-security/exploitdb is now a legacy pointer repo (near-
# empty) — the actively maintained one is on GitLab.
RUN apt-get update && apt-get install -y --no-install-recommends nmap git \
    && git clone --depth 1 https://gitlab.com/exploit-database/exploitdb /opt/exploitdb \
    && ln -s /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project

# XSS findings require real browser-side execution, not reflection alone.
RUN uv run playwright install --with-deps chromium

COPY . .
RUN uv sync

RUN mkdir -p /data/uploads

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
