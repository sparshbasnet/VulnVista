# VulnVista

> A controlled vulnerability-assessment platform for an isolated academic lab: a modular Python detection engine, FastAPI backend, PostgreSQL persistence, and a React/TypeScript dashboard covering fifteen vulnerability categories.

VulnVista detects, validates, stores, prioritises, and presents findings from intentionally vulnerable laboratory systems. It is being developed by **Group 7** for the **NIT6150 Advanced Project**. Unlike an orchestration layer around third-party scanners, each vulnerability category is checked by a purpose-built Python detector with its own safe test payload and validation logic — see [VulnVista_IMPLEMENTATION_PLAN.md](VulnVista_IMPLEMENTATION_PLAN.md) for the full eight-week roadmap and design detail.

> [!CAUTION]
> VulnVista is intended only for deliberately vulnerable applications in an isolated, pre-approved lab (DVWA, OWASP Juice Shop, Metasploitable2, a local TLS test service). Never use it to scan public, production, or third-party systems without explicit written authorization.

## Milestone tracker

Full per-vulnerability checklists live in the [implementation plan](VulnVista_IMPLEMENTATION_PLAN.md#8-eight-week-implementation-roadmap). Summary:

| Milestone | Target | Outcome | Status |
| --- | --- | --- | --- |
| M1 | Week 1 | Scope, architecture, and lab foundation | ✅ Complete |
| V1–V3 + M2 | Week 2 | Core scan framework + SQL injection, command injection, file upload | ✅ Complete |
| V4–V6 + M2B | Week 3 | + XSS, weak authentication, JWT/session | ✅ Complete |
| V7–V9 + M3A | Week 4 | + IDOR, sensitive files, path traversal; dashboard MVP | ✅ Complete |
| V10–V12 + M3 | Week 5 | + SSRF, vulnerable services, CSRF; full dashboard workflows | ✅ Complete |
| V13–V15 + M4/M5A | Week 6 | + XXE, weak TLS, security misconfiguration; integration, Docker, CI/CD | ✅ Complete |
| M5 | Week 7 | Detector validation, accuracy checks, release-candidate hardening | 🟡 Current stage |
| M6 | Week 8 | Final delivery, report, demonstration | ⬜ Pending |

## What VulnVista does

- Runs safe, repeatable detectors for fifteen vulnerability categories against approved lab targets only.
- Validates every finding (`NOT_DETECTED` → `SUSPECTED`/`CONFIRMED`/`INCONCLUSIVE`/`ERROR`) instead of reporting raw signals.
- Stores targets, scans, findings, and evidence in PostgreSQL behind a FastAPI backend.
- Maps findings to CWE, CVE, CVSS, and OWASP Top 10 categories where applicable.
- Presents severity, confidence, scan history, and remediation status on a React dashboard.
- Exports CSV and Word-openable findings reports from the same data shown on the dashboard.
- Isolates detector failures so one broken check never aborts a scan.

## High-level architecture

```mermaid
flowchart TD
    U["Authorised user"] --> TM["Target management"]
    TM --> SEL["Select scan / vulnerability modules"]
    SEL --> O["Scan orchestrator"]
    O --> PD["Python vulnerability detectors"]
    O --> TC["Service / TLS checks"]
    PD --> V["Validation framework"]
    TC --> V
    V --> F["Structured finding"]
    F --> DB["PostgreSQL"]
    DB --> API["FastAPI backend"]
    DB --> R["Reporting"]
    API --> D["React/TypeScript dashboard"]
    D --> RM["Finding review / remediation / re-scan"]
    RM --> O
```

## Approved lab targets

| Target | Role | Setup |
| --- | --- | --- |
| DVWA | Adjustable-difficulty vulnerability exercises | [lab/docker-compose.yml](lab/docker-compose.yml) |
| OWASP Juice Shop | Modern Node.js app covering the OWASP Top 10 | [lab/docker-compose.yml](lab/docker-compose.yml) |
| Metasploitable2 | Known-vulnerable service catalogue | [lab/docker-compose.yml](lab/docker-compose.yml) community image with mapped service ports |
| Local TLS test service | Weak TLS/certificate scenarios | [lab/tls-test/](lab/tls-test/) via [lab/docker-compose.yml](lab/docker-compose.yml) |

All targets run on an isolated `vulnvista_net` Docker network with no route to production infrastructure. See [lab/README.md](lab/README.md) for URLs, default credentials, and safety controls.

## Vulnerability categories

| # | Category | # | Category |
| --- | --- | --- | --- |
| 1 | SQL Injection | 9 | Weak Authentication Controls |
| 2 | Command Injection | 10 | Server-Side Request Forgery (SSRF) |
| 3 | Cross-Site Scripting (XSS) | 11 | XML External Entity (XXE) |
| 4 | Unrestricted File Upload | 12 | Sensitive-File Exposure |
| 5 | Path Traversal / File Inclusion | 13 | Known Vulnerable Services |
| 6 | Cross-Site Request Forgery (CSRF) | 14 | Security Misconfiguration |
| 7 | Broken Access Control / IDOR | 15 | Weak TLS Configuration |
| 8 | Authentication / Session / JWT Weaknesses | | |

Every detector implements the same `BaseDetector` contract (`backend/app/scanners/base.py`): a safe `check()`, an optional `validate()`, and a `build_finding()` that maps onto the shared schema below.

## Implementation stack

| Layer | Technology |
| --- | --- |
| Backend | FastAPI, SQLAlchemy (async), Alembic, [uv](https://docs.astral.sh/uv/) |
| Storage | PostgreSQL, bind-mounted to the host so data survives container restarts |
| Frontend | React 19, TypeScript, Vite, Tailwind CSS v4, react-router |
| Detection engine | Python, one module per vulnerability category under `backend/app/scanners/` |
| Deployment | Docker Compose (root stack + separate `lab/` compose for vulnerable targets) |
| CI/CD | GitHub Actions — backend lint/test, frontend lint/build, Docker image builds |

## Shared finding schema

Every detector result maps onto the same `Finding` model (`backend/app/models/finding.py`):

```text
id, scan_id, target_id, detector_id
vulnerability_name, severity, confidence
validation_status   # NOT_DETECTED | SUSPECTED | CONFIRMED | INCONCLUSIVE | ERROR
finding_status       # OPEN | IN_PROGRESS | REMEDIATED | ACCEPTED_RISK | FALSE_POSITIVE
description, affected_endpoint, parameter, evidence_summary, remediation
cwe, cve, cvss_score, owasp_category
created_at
```

Evidence (HTTP request/response pairs, screenshots, TLS results, service banners, etc.) is stored separately per finding via the `Evidence` model, so a finding stays lightweight while still being fully reproducible.

## Dashboard views

- Severity, category, and target distribution.
- Findings table with filtering by target, severity, confidence, and validation status.
- Evidence viewer with request/response details, CWE/CVE/CVSS/OWASP mapping, and remediation guidance.
- Target management, discovery, scope selection, scan creation, and scan status tracking.
- User account management for administrators, forced password change, self-service reset token flow, and account page.
- Remediation status tracking plus CSV and Word-openable report export.

## Quality and safety checklist

- Detectors run only against the approved target allowlist — no arbitrary public hosts.
- Only synthetic accounts, files, and data are used or seeded.
- No destructive payloads, no denial-of-service, no automatic exploitation for system control.
- A detector failure never aborts the rest of a scan.
- Every finding retains a detector ID, scan ID, and evidence for reproducibility.
- The environment runs reproducibly with Docker Compose; secrets stay out of Git.

Full checklist: [implementation plan §18](VulnVista_IMPLEMENTATION_PLAN.md#18-security-and-ethical-controls-checklist).

## Standards and methodology

| Area | Standard | Project use |
| --- | --- | --- |
| Vulnerability classes | OWASP Top 10 | Structures the detector catalogue and dashboard categories |
| Weakness classification | CWE | Attached to each finding where applicable |
| Known-vulnerability tracking | CVE | Attached to vulnerable-service findings |
| Technical severity | CVSS v3.1 | Consistent severity baseline where a score applies |

## Definition of done

Full checklist: [implementation plan §20](VulnVista_IMPLEMENTATION_PLAN.md#20-final-definition-of-project-done). Summary — the project is complete when:

- [x] All four approved lab targets are represented in the isolated lab setup.
- [x] All fifteen detectors are implemented and share a common schema.
- [x] Findings, evidence, severity, and confidence persist in PostgreSQL.
- [x] The dashboard presents findings, scan history, evidence, and remediation status.
- [x] CSV/DOC report export, Docker deployment, and CI/CD workflow are implemented.
- [ ] Evaluation metrics (detection rate, false-positive/negative rate, repeatability) are calculated.
- [ ] Documentation, academic report, and final demonstration are complete.

## Team workflow

1. Create a branch for each issue or milestone task.
2. Keep commits focused and reference the related requirement or checklist item.
3. Require another team member to review detector, schema, and safety-control changes.
4. Do not commit real credentials, `.env` files, or generated evidence containing sensitive data.
5. Update this README's milestone table as milestones are reviewed and accepted.

## Project status

**Current phase:** Week 7 — validation and release-candidate hardening. The authenticated backend, React dashboard, Docker setup, CI workflow, target discovery/scope support, scan orchestration, persistence, reporting export, Bruno API collection, and all fifteen detector modules are implemented.
**Overall progress:** M4/M5A complete, 15/15 detectors implemented. Remaining work is validation evidence, metrics, final documentation/report polish, and the Week 8 demonstration/submission package.

## Monorepo quickstart

The repository is structured as a monorepo: [backend/](backend/) (FastAPI + PostgreSQL),
[frontend/](frontend/) (React/TypeScript), [lab/](lab/) (vulnerable scan targets), plus
`docs/`, `scripts/`, and `.github/workflows/`. See
[VulnVista_IMPLEMENTATION_PLAN.md](VulnVista_IMPLEMENTATION_PLAN.md) for the full
architecture and roadmap.

### Prerequisites

- Docker and Docker Compose v2
- (Optional, for running outside Docker) [uv](https://docs.astral.sh/uv/) for the
  backend and Node.js 20+ for the frontend

### First run

Before the first start, copy `.env.example` to `.env`, then set:

- `DATABASE_URL` to the Neon pooled connection string using the `postgresql+asyncpg://` prefix and `?ssl=require`.
- `SECRET_KEY` to a strong random value.
- `INITIAL_ADMIN_USERNAME`, `INITIAL_ADMIN_EMAIL`, and `INITIAL_ADMIN_PASSWORD`.

The backend applies Alembic migrations on startup and creates the initial admin
account once; subsequent starts do not overwrite it.

```bash
./scripts/setup.sh        # creates ./storage, copies .env.example -> .env, creates the shared network
docker compose up --build # starts backend + frontend; database is Neon
```

- Backend API: <http://localhost:9000/api/health>
- Frontend dashboard: <http://localhost:5173>

Sign in with `INITIAL_ADMIN_USERNAME` (or `INITIAL_ADMIN_EMAIL`) and
`INITIAL_ADMIN_PASSWORD`. Admins can create platform users through
`POST /api/auth/users`; analysts can create targets and scans, while viewers have
read-only access.

### Database

VulnVista now uses Neon as the primary PostgreSQL database. Use the pooled Neon
connection string for the backend:

```env
DATABASE_URL=postgresql+asyncpg://USER:PASSWORD@ep-xxxx-pooler.REGION.aws.neon.tech/DBNAME?ssl=require
```

For one-off migration work outside the container, Neon recommends the direct
non-pooler host. The container entrypoint runs `alembic upgrade head`
automatically against `DATABASE_URL`; set `RUN_MIGRATIONS=0` if migrations are
handled separately.

### Local persistence

Scan evidence and optional local lab state live on the host under `./storage/`
(git-ignored), bind-mounted into the containers:

- `./storage/uploads` — backend-collected scan evidence / uploaded files
- `./storage/lab/juice-shop` — OWASP Juice Shop challenge/user state

`docker compose down`, a host reboot, or `docker compose up` again all leave this
data untouched. Only manually deleting `./storage` removes it.

### Optional local database

For offline/local-only development, start the bundled PostgreSQL container with
the `local-db` profile and point `DATABASE_URL` at it:

```bash
DATABASE_URL=postgresql+asyncpg://vulnvista:change-me-in-dev@postgres:5432/vulnvista \
  docker compose --profile local-db up --build
```

When the local profile is enabled, PostgreSQL data is stored under
`./storage/postgres`.

### Lab targets

DVWA and OWASP Juice Shop run from a separate compose file so the core app stack stays
fast and independent of them. Both compose files attach to the shared `vulnvista_net`
network as external, so run `./scripts/setup.sh` once first (it creates the network)
before starting either one:

```bash
docker compose --env-file .env -f lab/docker-compose.yml up -d
```

See [lab/README.md](lab/README.md) for target URLs, credentials, and
Metasploitable2 service-port mappings.

---

VulnVista is an academic defensive-security project. All testing must remain authorized, isolated, contained, and reproducible.
