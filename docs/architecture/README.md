# VulnVista — Architecture Documentation

## 1. Overview

VulnVista is a controlled vulnerability-assessment platform used to detect, validate, store, prioritise, and present findings from intentionally vulnerable laboratory systems (DVWA, OWASP Juice Shop, Metasploitable 2, and a local TLS test service). The system is composed of a Python/FastAPI backend, a PostgreSQL data store, a React/TypeScript dashboard, a modular detector framework, and a containerised deployment with CI/CD.

This document describes the system's logical architecture, component responsibilities, data model, request/data flow, and the safety boundary that constrains the platform to approved laboratory targets only.

---

## 2. Architectural Goals

| Goal | Description |
|---|---|
| Modularity | Each of the 15 vulnerability categories is an independently pluggable detector conforming to one shared interface. |
| Safety by construction | The system can only run against an explicit allowlist of laboratory targets; destructive or exploit-grade actions are disallowed at the framework level. |
| Auditability | Every scan, detector execution, and finding is persisted with evidence sufficient for manual reproduction. |
| Separation of concerns | Detection, validation, persistence, presentation, and reporting are distinct layers connected through well-defined contracts (result schema, API, database models). |
| Resilience | A failure in one detector must not terminate an entire scan. |
| Reproducibility | Any environment should be able to stand up the full stack from source using Docker Compose and documented setup steps. |

---

## 3. System Context

```text
                        ┌───────────────────────────┐
                        │      Authorised User       │
                        └──────────────┬─────────────┘
                                       │ HTTPS
                                       ▼
                        ┌───────────────────────────┐
                        │  React / TypeScript UI     │
                        │  (Dashboard)                │
                        └──────────────┬─────────────┘
                                       │ REST (JSON)
                                       ▼
                        ┌───────────────────────────┐
                        │      FastAPI Backend       │
                        │  (API + Scan Orchestrator) │
                        └───┬───────────────────┬────┘
                            │                   │
                 detector calls           persistence
                            │                   │
                            ▼                   ▼
                ┌───────────────────┐  ┌───────────────────┐
                │  Detector Engine   │  │   PostgreSQL       │
                │ (15 modules)       │  │ (targets, scans,   │
                └─────────┬──────────┘  │ findings, evidence)│
                          │             └───────────────────┘
                          ▼
                ┌───────────────────────────┐
                │ Isolated Laboratory Network │
                │  DVWA · Juice Shop ·        │
                │  Metasploitable 2 ·         │
                │  Local TLS test service     │
                └───────────────────────────┘
```

The dashboard never talks to laboratory targets directly — all detection activity is mediated by the backend, which enforces the target allowlist before any detector runs.

---

## 4. Layered Architecture

VulnVista is organised into six logical layers, each with a single responsibility:

1. **Access-control layer** — JWT-based authentication and role-based authorisation (`ADMIN`, `ANALYST`/operator, `VIEWER`) guarding every non-public route. Covers login, forced password change on first login, self-service password-reset tokens, and admin-managed user accounts. This secures the VulnVista platform itself, distinct from any detector that tests a *target's* authentication.
2. **Presentation layer** — React/TypeScript dashboard. Renders targets, scans, findings, evidence, and reports; issues no direct network calls to lab targets.
3. **API layer** — FastAPI routers under `/api/*`. Validates input, enforces authorisation and allowlisting, and exposes CRUD/query operations over targets, discoveries, scans, detectors, findings, and evidence.
4. **Orchestration layer** — Scan Orchestrator + Detector Registry + Discovery Runner. Resolves which detectors to run for a scan profile, manages concurrency, timeouts, and per-detector exception isolation; the Discovery Runner crawls an approved target to propose in-scope/out-of-scope paths before a scan runs.
5. **Detection layer** — 15 independent detector modules implementing a common `BaseDetector` interface (`check`, `validate`, `build_finding`). Each detector only interacts with the approved lab target it was invoked against.
6. **Persistence layer** — SQLAlchemy models mapped to PostgreSQL (Neon-hosted) tables for users, targets, discoveries, scans, findings, and evidence.

Each layer only depends on the layer directly below it; the detection layer has no awareness of the API or presentation layers, which keeps detectors independently testable.

---

## 5. Component Breakdown

### 5.1 FastAPI Backend

- **`app/api/`** — route handlers for `/auth`, `/targets`, `/discoveries`, `/scans`, `/findings`. There is no backend `/reports` route — report export is generated client-side (see 5.4).
- **`app/api/auth_deps.py`** — FastAPI dependencies (`require_operator`, etc.) that verify the JWT and enforce role checks on every protected route.
- **`app/core/`** — configuration, allowlist enforcement, logging, safety controls (rate limits, timeouts).
- **`app/database/`** — SQLAlchemy engine/session setup, migrations (Alembic, applied on startup against Neon).
- **`app/models/`** — ORM models (User, Target, Discovery, Scan, Finding, Evidence).
- **`app/schemas/`** — Pydantic request/response schemas.
- **`app/services/`** — scan orchestration, detector registry, discovery runner (crawls a target to propose in-scope/out-of-scope paths).
- **`app/scanners/`** — the 15 detector modules plus `base.py` defining the shared interface. One detector (`command_injection.py`) also supports an opt-in OWASP ZAP active-scan cross-check (`ScanContext.extra['use_zap']`) that corroborates the manual finding without changing its own probe logic.

### 5.2 Detector Engine

Each detector is a self-contained module implementing:

```python
class BaseDetector:
    detector_id: str
    name: str
    vulnerability_type: str
    supported_targets: list[str]

    async def check(self, context): ...
    async def validate(self, result): ...
    def build_finding(self, result): ...
```

The **Scan Orchestrator** resolves the list of detectors for a chosen scan profile, invokes each detector inside an isolated exception boundary, applies a per-detector timeout, and forwards successful results to the persistence layer as `Finding` + `Evidence` records. A single detector failure is recorded as an error and does not abort the remaining detectors.

### 5.3 Database (PostgreSQL via Neon)

The primary datastore is a managed **Neon** Postgres instance (pooled `postgresql+asyncpg://` connection string), not a locally-run container — Alembic migrations run automatically against it on backend startup. A bundled local Postgres container remains available behind a `local-db` Compose profile for fully offline development.

Core tables map directly to the business objects defined in the implementation plan:

- `users` — platform operator accounts (`ADMIN` / `ANALYST` / `VIEWER`), hashed passwords, forced-password-change and password-reset-token state.
- `targets` — approved lab hosts (`is_allowed` flag enforced at write time).
- `discoveries` — one row per crawl of a target, producing the candidate `in_scope_paths` / `out_of_scope_paths` a scan will attack.
- `scans` — one row per scan execution, with lifecycle status (`QUEUED → RUNNING → COMPLETED/PARTIAL/FAILED/CANCELLED`), and the resolved scope carried over from its discovery.
- `findings` — one row per confirmed/suspected vulnerability, linked to `scan_id`, `target_id`, `detector_id`.
- `evidence` — supporting artefacts (HTTP request/response pairs, timing data, screenshots, TLS/cert data, etc.), linked to a finding.

Findings and evidence are intentionally normalised into separate tables so that evidence payloads (which can be large — screenshots, full HTTP bodies) don't bloat the primary findings table used for dashboard queries.

### 5.4 React/TypeScript Dashboard

- **`pages/`** — Login, ForgotPassword, ResetPassword, ForcedPasswordChange, Dashboard, Targets, Scans, Findings, Evidence, Account, Users (admin-only).
- **`components/`** — findings table/cards, evidence viewer, scope tree (discovery path selection), layout/navigation.
- **`services/` / `auth/`** — typed API client wrapping the backend REST endpoints, plus the auth context/hook and protected-route wrappers that redirect unauthenticated users to `/login`.
- **`hooks/`** — data-fetching and polling hooks (e.g., scan status polling while `RUNNING`).
- **`lib/report.ts`** — generates the CSV and Word-openable (`.doc`) findings export **client-side** from the already-loaded findings data; there is no backend report-rendering endpoint.
- **`types/`** — TypeScript types mirroring the backend Pydantic schemas.

### 5.5 Laboratory Network

DVWA, OWASP Juice Shop, Metasploitable 2, and a local TLS test service run as isolated containers/VMs on a private network, unreachable from outside the lab. The backend's allowlist is the only mechanism permitted to select a target, so no detector can be pointed at an unapproved or public host.

---

## 6. Data Model Summary

```text
User (platform account)

Target 1───* Discovery
       │
       └──1───* Scan 1───* Finding 1───* Evidence
                │
                └──uses──> Detector (metadata/registry, not a DB-owned FK to findings' source-of-truth)
```

| Entity | Key Fields | Notes |
|---|---|---|
| User | `id, username, email, hashed_password, role, is_active, must_change_password, last_login_at` | Platform login/access-control account — separate from any lab-target credentials a detector uses. |
| Target | `id, name, target_type, base_url, ip_address, environment, is_allowed` | `is_allowed` is checked before every scan. |
| Discovery | `id, target_id, status, in_scope_paths, out_of_scope_paths, initiated_by` | Crawls a target and proposes the path scope a scan will attack; a scan carries this scope forward. |
| Scan | `id, target_id, scan_profile, status, started_at, completed_at, duration, initiated_by, error_summary` | One row per execution. |
| Finding | `id, scan_id, target_id, detector_id, vulnerability_name, severity, confidence, validation_status, finding_status, cwe, cve, cvss_score, owasp_category` | `validation_status` and `finding_status` (remediation) are tracked independently. |
| Evidence | type-specific payload (request/response, timing, screenshot, TLS data, etc.) | Stored separately from findings to keep the findings table lean. |

**Status vocabularies:**

- Scan status: `QUEUED, RUNNING, COMPLETED, PARTIAL, FAILED, CANCELLED`
- Validation status: `NOT_DETECTED, SUSPECTED, CONFIRMED, INCONCLUSIVE, ERROR`
- Finding (remediation) status: `OPEN, IN_PROGRESS, REMEDIATED, ACCEPTED_RISK, FALSE_POSITIVE`

Keeping validation status and finding/remediation status as separate fields lets the system distinguish "did the detector confirm this vulnerability exists" from "what is the team doing about it" — these are different concerns with different lifecycles.

---

## 7. Request / Data Flow

### 7.1 Running a Scan (end-to-end)

```text
0. User logs in (POST /api/auth/login) and the dashboard attaches the returned
   JWT to every subsequent request; unauthenticated calls are rejected
1. User optionally runs a Discovery (POST /discoveries) to crawl the target
   and picks in-scope/out-of-scope paths from the result in the Scope Tree
2. User selects Target + Detectors + Scan Profile in the dashboard
3. Dashboard → POST /scans  (backend validates target.is_allowed)
4. Backend creates Scan row (status=QUEUED), returns scan_id
5. Orchestrator transitions Scan to RUNNING
6. For each selected detector (isolated, timeout-bound):
     a. detector.check(context)      → raw result
     b. detector.validate(result)    → validation_status
     c. detector.build_finding(...)  → common Finding schema
     d. Persist Finding + Evidence
     e. On exception: record error_summary for that detector, continue
7. Orchestrator sets Scan status = COMPLETED / PARTIAL / FAILED
8. Dashboard polls GET /scans/{id} and GET /scans/{id}/findings
9. User opens a Finding → GET /findings/{id} (includes evidence, CWE/CVE/CVSS, remediation)
10. User updates remediation status → PATCH /findings/{id}/status
11. User exports a report → the dashboard generates CSV/Word (.doc) client-side
    from the findings already loaded (frontend/src/lib/report.ts) — no
    backend round-trip is involved
```

### 7.2 Detector Result Contract

All 15 detectors emit the same shape, regardless of vulnerability category:

```json
{
  "detector": "sql_injection",
  "vulnerability": "SQL Injection",
  "detected": true,
  "validation_status": "CONFIRMED",
  "severity": "CRITICAL",
  "confidence": "HIGH",
  "endpoint": "/vulnerabilities/sqli/",
  "parameter": "id",
  "evidence": {},
  "remediation": "...",
  "cwe": "CWE-89"
}
```

This shared contract is what allows the orchestrator, database, API, and dashboard to remain generic — none of them need vulnerability-specific logic; only the detector modules do.

---

## 8. Safety Architecture

Safety is enforced structurally, not just procedurally:

- **Target allowlist**: every scan request is checked against `Target.is_allowed` before any detector executes; unapproved/public hosts are rejected at the API boundary.
- **Non-destructive payloads**: detectors use harmless markers, timing canaries, and seeded controlled files/objects rather than destructive commands, real exploitation, or malware.
- **Timeouts and rate limits**: enforced per detector and per scan to bound impact on lab targets.
- **Exception isolation**: a detector raising an error is caught by the orchestrator and recorded, never allowed to crash the scan or corrupt shared state.
- **Audit logging**: every scan and detector execution is logged for traceability.
- **Secrets hygiene**: `.env.example` documents required configuration without committing real secrets; CI includes a check to prevent secret leakage.

---

## 9. Deployment Architecture

```text
┌─────────────────────────── docker-compose.yml ───────────────────────────┐
│                                                                            │
│  ┌───────────────┐   ┌───────────────┐                                  │
│  │  frontend      │   │  backend       │──────────────┐                  │
│  │  (React build, │──▶│  (FastAPI,     │              │                  │
│  │  served static)│   │  Uvicorn)      │              ▼                  │
│  └───────────────┘   └───────┬───────┘   ┌───────────────────────────┐  │
│                               │           │  Neon (managed Postgres,  │  │
│                               │           │  pooled connection)       │  │
│                               │           └───────────────────────────┘  │
│                               ▼                                          │
│                  ┌───────────────────────────┐                          │
│                  │ Private lab network        │                          │
│                  │ (dvwa, juice-shop,          │                          │
│                  │  metasploitable, tls-test)  │                          │
│                  └───────────────────────────┘                          │
└────────────────────────────────────────────────────────────────────────┘
```

- The frontend and backend each have their own Dockerfile; laboratory targets live under `lab/` with their own compose definitions on an isolated network segment.
- Postgres is Neon-hosted by default (`DATABASE_URL` points at Neon's pooled endpoint); a local `postgres` container remains available behind an opt-in `local-db` Compose profile for offline development, with `./storage/postgres` as its persistent volume.
- Scan evidence/uploads and lab state persist on the host under `./storage/`, bind-mounted into the containers, so they survive `docker compose down` and reboots.
- Health checks gate service readiness before the orchestrator accepts scan requests.
- CI/CD (GitHub Actions) runs lint → unit tests → backend tests → frontend build → Docker build → integration checks on every push/PR, and produces a release-candidate build once validated.

---

## 10. Extensibility Boundary

The core 8-week implementation is intentionally scoped to the 15 built-in detectors operating only against the four approved lab targets. A documented future extension point allows external tool output (e.g., Nmap, OWASP ZAP, Nikto, Trivy, Nuclei) to be normalised into the same Finding/Evidence schema via an adapter layer, without changing the core database, API, or dashboard:

```text
External Tool Output → VulnVista Adapter → Normalise → Shared Finding Schema → Dashboard/Reports/History
```

This keeps the core architecture stable while leaving a clear seam for later integration work, which is explicitly out of scope for the initial delivery.

---

## 11. Summary

VulnVista's architecture separates *what* is detected (pluggable detector modules behind one interface) from *how* results are stored, queried, and displayed (a stable schema flowing through FastAPI → PostgreSQL → React dashboard). Safety constraints — target allowlisting, non-destructive payloads, timeouts, and exception isolation — are enforced in the orchestration layer so that every detector, regardless of vulnerability category, inherits the same controlled-lab guarantees by construction.
