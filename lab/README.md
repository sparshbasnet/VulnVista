# VulnVista lab targets

> [!CAUTION]
> Everything in this folder is deliberately vulnerable. Run it only on an isolated
> Docker network with no route to production or public infrastructure. Never point
> a VulnVista scan at anything outside this lab.

This compose file brings up the intentionally vulnerable applications used as scan
targets, per the [implementation plan](../VulnVista_IMPLEMENTATION_PLAN.md#1-purpose):
DVWA, OWASP Juice Shop, Metasploitable2, and a deliberately-weak-TLS nginx target. See
[`METASPLOITABLE.md`](./METASPLOITABLE.md) for details on the Metasploitable2
container (its services start via a boot script, not just `docker run`) and a
higher-fidelity VM alternative.

## Prerequisites

Run `../scripts/setup.sh` (or `docker network create vulnvista_net`) once before
starting this file. Neither this compose file nor the root one creates the shared
`vulnvista_net` network themselves — both attach to it as `external: true` so the two
compose projects never fight over owning it. If you see a `network vulnvista_net not
found` error, run setup.sh first.

## Usage

Run these from the repository root, so the shared `.env` file is picked up:

```bash
# Start DVWA + Juice Shop + Metasploitable2 + tls-test
# --build is only needed the first time (or after editing tls-test/Dockerfile) —
# it's the one target built locally rather than pulled from a registry.
docker compose --env-file .env -f lab/docker-compose.yml up -d --build

# Stop them (data in ./storage/lab persists)
docker compose --env-file .env -f lab/docker-compose.yml down
```

## Targets

| Target | URL | Default credentials | Persistence |
| --- | --- | --- | --- |
| DVWA | <http://localhost:8080> (`DVWA_PORT`) | `admin` / `password` | Stateless — reset via its own "Create / Reset Database" page. |
| OWASP Juice Shop | <http://localhost:3000> (`JUICE_SHOP_PORT`) | No login required to browse; challenges create their own accounts | Bind-mounted to `./storage/lab/juice-shop` on the host, so challenge progress survives restarts. |
| Metasploitable2 | Many services, each at `localhost:<real-port>+10000` (e.g. `localhost:10022` for SSH) | `msfadmin` / `msfadmin` | Stateless — see [`METASPLOITABLE.md`](./METASPLOITABLE.md) for the full port list and details. |
| tls-test | <https://localhost:8443> (`TLS_TEST_PORT`) — expect a browser cert warning, that's the point | None | Stateless — static page, no data. |

From inside the backend container (or once detectors run), these are reachable at
`http://dvwa`, `http://juice-shop`, `metasploitable2:<real-port>`, and `tls-test:443`
(not `:8443` — that's only the host-side mapping) on `vulnvista_net`.

## Safety controls

Per the implementation plan's safety checklist:

- Only run this against the allowlisted targets defined here — never add arbitrary
  public hosts to this file.
- Keep `vulnvista_net` isolated; don't bridge it onto a network with production or
  personal-data systems.
- Use only synthetic accounts, files, and data when seeding or exercising these targets.
