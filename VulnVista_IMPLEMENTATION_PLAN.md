# VulnVista Implementation Plan

## 1. Purpose

This implementation plan converts the approved VulnVista proposal into an eight-week development roadmap from project setup through final delivery.

VulnVista will be implemented as a controlled vulnerability-assessment platform that detects, validates, stores, prioritises, and presents findings from intentionally vulnerable laboratory systems. The implementation will cover fifteen vulnerability categories and integrate them into a common FastAPI backend, PostgreSQL database, React dashboard, containerised deployment, CI/CD workflow, reporting module, an authenticated login/access-control system, and evaluation process.

The project must remain restricted to approved laboratory targets such as:

- Damn Vulnerable Web Application (DVWA)
- OWASP Juice Shop
- Metasploitable 2
- A local controlled HTTPS/TLS test service
- Any additional controlled endpoint created only when required to demonstrate a proposed detector

The implementation period is limited to **8 weeks**.

---

# 2. Project Goals

The implementation must deliver:

1. A reproducible isolated vulnerability-testing laboratory.
2. A modular Python vulnerability detection engine.
3. Fifteen vulnerability-specific detection modules.
4. Safe and repeatable validation logic for every vulnerability.
5. A shared finding and evidence format.
6. A FastAPI backend for target, scan, finding, and remediation management.
7. PostgreSQL persistence.
8. A React/TypeScript dashboard.
9. Severity, confidence, CWE, CVE, CVSS, and OWASP mappings where applicable.
10. Scan history and remediation tracking.
11. HTML/PDF report export.
12. Docker-based deployment.
13. GitHub Actions CI/CD.
14. Automated and manual detector validation.
15. **A login/authentication and access-control system for the platform itself.**
16. Final technical documentation, academic report, presentation, and demonstration.

---

# 2A. Team Responsibilities and Vulnerability Ownership

The fifteen vulnerability detectors are split equally between the three team members. Each person owns five detectors end-to-end (detector logic, safe payloads, validation, evidence, tests, and documentation for their modules).

| Person | # | Vulnerability | File |
|---|---|---|---|
| **Nischal** | 1 | CSRF | `csrf.py` |
| | 2 | Path Traversal | `path_traversal.py` |
| | 3 | File Upload | `file_upload.py` |
| | 4 | JWT / Session Security | `jwt_session.py` |
| | 5 | Security Misconfiguration | `misconfiguration.py` |
| **Sparsh** | 1 | SQL Injection | `sql_injection.py` |
| | 2 | Cross-Site Scripting (XSS) | `xss.py` |
| | 3 | Broken Access Control / IDOR | `idor.py` |
| | 4 | Server-Side Request Forgery (SSRF) | `ssrf.py` |
| | 5 | XML External Entity (XXE) | `xxe.py` |
| **Sunil** | 1 | Command Injection | `command_injection.py` |
| | 2 | Vulnerable Services | `vulnerable_services.py` |
| | 3 | Sensitive Files | `sensitive_files.py` |
| | 4 | Weak Authentication | `weak_auth.py` |
| | 5 | Weak TLS | `weak_tls.py` |

### Working model

Detector development runs **in parallel**. In each vulnerability week, **Sparsh works on one vulnerability, Sunil works on another, and Nischal works on another** — three detectors are produced per week (one per person). Across five vulnerability weeks (Weeks 2–6) this delivers all fifteen detectors.

### Parallel weekly vulnerability schedule

| Week | Sparsh | Sunil | Nischal |
|---|---|---|---|
| **Week 2** | SQL Injection | Command Injection | File Upload |
| **Week 3** | Cross-Site Scripting (XSS) | Weak Authentication | JWT / Session Security |
| **Week 4** | Broken Access Control / IDOR | Sensitive Files | Path Traversal |
| **Week 5** | Server-Side Request Forgery (SSRF) | Vulnerable Services | CSRF |
| **Week 6** | XML External Entity (XXE) | Weak TLS | Security Misconfiguration |

Shared platform work (backend, database, dashboard, reporting, containers, CI/CD, auth) is layered on top of these weeks and is a shared responsibility, as described in Section 14.

---

# 3. High-Level System Workflow

```text
Authorised User
      |
      v
Login / Authentication  <-- platform access control
      |
      v
Target Management
      |
      v
Select Scan / Vulnerability Modules
      |
      v
Scan Orchestrator
      |
      +-----------------------------+
      |                             |
      v                             v
Python Vulnerability Detectors   Service/TLS Checks
      |                             |
      +-------------+---------------+
                    |
                    v
          Validation Framework
                    |
                    v
          Structured Finding
                    |
                    v
              PostgreSQL
                    |
          +---------+----------+
          |                    |
          v                    v
      FastAPI API          Reporting
          |
          v
 React/TypeScript Dashboard
          |
          v
Finding Review / Remediation / Re-scan
```

---

# 4. Core Business Objects

The implementation should distinguish the following objects.

## 4.0 User (Platform Account)

Represents an authenticated operator of the VulnVista platform.

Suggested fields:

- `id`
- `username`
- `email`
- `hashed_password`
- `role` (`ADMIN`, `ANALYST`, `VIEWER`)
- `is_active`
- `last_login_at`
- `created_at`
- `updated_at`

Suggested roles:

```text
ADMIN    -> manage users, targets, scans, findings
ANALYST  -> create/run scans, update finding status
VIEWER   -> read-only access to findings and reports
```

## 4.1 Target

Represents an approved laboratory host/application.

Suggested fields:

- `id`
- `name`
- `target_type`
- `base_url`
- `ip_address`
- `environment`
- `is_allowed`
- `created_at`
- `updated_at`

## 4.1A Discovery (delivered beyond the original scope)

Represents one crawl of a `Target`, run ahead of a scan to propose which paths are actually in scope for the detectors to attack. Implemented as `backend/app/models/discovery.py`, `POST/GET /api/discoveries`, and rendered in the dashboard's Scope Tree (`frontend/src/components/ScopeTree.tsx`). A `Scan` carries the resolved scope forward from its `Discovery` so a detector profile switch doesn't silently re-run discovery.

Fields:

- `id`
- `target_id`
- `status`
- `in_scope_paths`
- `out_of_scope_paths`
- `initiated_by`
- `created_at`

## 4.2 Scan

Represents one execution of selected detectors against a target.

Suggested fields:

- `id`
- `target_id`
- `scan_profile`
- `status`
- `started_at`
- `completed_at`
- `duration`
- `initiated_by`
- `error_summary`

Suggested statuses:

```text
QUEUED
RUNNING
COMPLETED
PARTIAL
FAILED
CANCELLED
```

## 4.3 Detector

Represents one vulnerability-specific Python module.

Suggested metadata:

- detector ID
- detector name
- vulnerability category
- supported target
- version
- severity default
- timeout
- validation strategy
- **owner (team member)**

## 4.4 Finding

Represents a vulnerability reported by a detector.

Suggested fields:

- `id`
- `scan_id`
- `target_id`
- `detector_id`
- `vulnerability_name`
- `severity`
- `confidence`
- `validation_status`
- `description`
- `affected_endpoint`
- `parameter`
- `evidence_summary`
- `remediation`
- `cwe`
- `cve`
- `cvss_score`
- `owasp_category`
- `finding_status`
- `created_at`

## 4.5 Evidence

Evidence should be stored separately when possible.

Possible evidence types:

- HTTP request
- HTTP response
- response comparison
- response time
- browser execution screenshot/result
- token claims
- file accessibility result
- service banner
- software version
- TLS protocol result
- certificate data
- redirect/callback evidence

## 4.6 Finding Status

```text
OPEN
IN_PROGRESS
REMEDIATED
ACCEPTED_RISK
FALSE_POSITIVE
```

## 4.7 Validation Status

Keep validation separate from remediation.

```text
NOT_DETECTED
SUSPECTED
CONFIRMED
INCONCLUSIVE
ERROR
```

---

# 5. Repository and Project Structure

A possible repository layout:

```text
vulnvista/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── auth_deps.py     # request-time auth/role dependencies
│   │   │   └── v1/
│   │   │       ├── auth.py      # login / token / user management
│   │   │       ├── targets.py
│   │   │       ├── discoveries.py  # target crawl + scope proposal
│   │   │       ├── scans.py
│   │   │       └── findings.py
│   │   ├── core/
│   │   │   ├── security.py      # password hashing, JWT, deps
│   │   │   └── ...
│   │   ├── database/
│   │   ├── models/
│   │   │   ├── user.py          # platform account model
│   │   │   ├── discovery.py     # crawl + scope proposal
│   │   │   └── ...
│   │   ├── schemas/
│   │   ├── services/
│   │   │   ├── discovery_runner.py
│   │   │   └── ...
│   │   ├── scanners/
│   │   │   ├── base.py
│   │   │   ├── sql_injection.py         # Sparsh
│   │   │   ├── command_injection.py     # Sunil
│   │   │   ├── xss.py                    # Sparsh
│   │   │   ├── file_upload.py           # Nischal
│   │   │   ├── idor.py                   # Sparsh
│   │   │   ├── jwt_session.py           # Nischal
│   │   │   ├── path_traversal.py        # Nischal
│   │   │   ├── csrf.py                   # Nischal
│   │   │   ├── vulnerable_services.py    # Sunil
│   │   │   ├── misconfiguration.py       # Nischal
│   │   │   ├── ssrf.py                   # Sparsh
│   │   │   ├── xxe.py                    # Sparsh
│   │   │   ├── sensitive_files.py        # Sunil
│   │   │   ├── weak_auth.py              # Sunil
│   │   │   └── weak_tls.py               # Sunil
│   │   └── main.py
│   ├── tests/
│   ├── pyproject.toml
│   └── Dockerfile
│
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Login.tsx              # login screen
│   │   │   ├── ForgotPassword.tsx     # password-reset request
│   │   │   ├── ResetPassword.tsx      # password-reset completion
│   │   │   ├── ForcedPasswordChange.tsx
│   │   │   ├── Account.tsx
│   │   │   ├── Users.tsx              # admin-only user management
│   │   │   └── ...
│   │   ├── components/
│   │   │   └── ScopeTree.tsx    # discovery in-scope/out-of-scope path picker
│   │   ├── auth/                # auth context/hook, protected-route wrapper
│   │   ├── services/
│   │   ├── lib/
│   │   │   └── report.ts        # client-side CSV/Word findings export
│   │   ├── hooks/
│   │   └── types/
│   ├── package.json
│   └── Dockerfile
│
├── lab/
│   ├── dvwa/
│   ├── juice-shop/
│   ├── metasploitable/
│   └── tls-test-service/
│
├── docs/
│   ├── architecture/
│   ├── detectors/
│   ├── api/
│   ├── testing/
│   └── screenshots/
│
├── scripts/
├── .github/
│   └── workflows/
├── docker-compose.yml
├── .env.example
├── README.md
└── VulnVista_IMPLEMENTATION_PLAN.md
```

---

# 5A. Platform Authentication / Login System

VulnVista must sit behind a login so that only authorised operators can manage targets, run scans, and view findings. This is separate from the JWT/session **detector** (which tests a target's authentication) — this component secures VulnVista itself.

## Design

- Token-based authentication (JWT access token, optional refresh token).
- Passwords stored using a strong one-way hash (e.g. bcrypt/argon2).
- Role-based access control (`ADMIN`, `ANALYST`, `VIEWER`).
- Protected backend routes via a FastAPI dependency that verifies the token and role.
- Protected frontend routes (redirect to `/login` when unauthenticated; hide privileged actions by role).
- Seed one initial admin account via environment variables/migration for first login.
- Audit the identity of the user who initiates each scan (`scan.initiated_by`).

## Auth tasks

- [x] Add `User` model and migration.
- [x] Add password hashing utilities.
- [x] Add JWT creation/verification utilities.
- [x] Implement `POST /api/auth/login`.
- [ ] Implement `POST /api/auth/logout` (or token invalidation strategy). — *Delivered as client-side token discard rather than a server-side invalidation endpoint.*
- [x] Implement `GET /api/auth/me`.
- [x] Implement `POST /api/auth/users` (admin-only user creation).
- [x] Add auth dependency to protect all non-public routes. — *`app/api/auth_deps.py` (`require_operator`, etc.).*
- [x] Enforce role checks on privileged endpoints.
- [x] Build frontend login page and auth context/hook.
- [x] Add protected-route wrapper and token storage handling.
- [x] Seed initial admin account from environment configuration.
- [x] Add auth unit/API tests (valid login, invalid login, expired token, role denial).

**Delivered beyond the original scope:**

- [x] Forced password change on first login (`ForcedPasswordChange.tsx`).
- [x] Self-service password-reset token flow (`ForgotPassword.tsx`, `ResetPassword.tsx`).
- [x] Account settings page for the signed-in user (`Account.tsx`).
- [x] Admin user-management page beyond raw `POST /users` (`Users.tsx`).

The auth system is scaffolded in **Week 1** and completed in **Week 2** so that every later feature is built behind it.

---

# 6. Common Detector Interface

All fifteen detectors should use the same interface.

Example conceptual structure:

```python
class BaseDetector:
    detector_id: str
    name: str
    vulnerability_type: str
    supported_targets: list[str]
    owner: str  # Nischal / Sparsh / Sunil

    async def check(self, context):
        ...

    async def validate(self, result):
        ...

    def build_finding(self, result):
        ...
```

A detector should return a common result structure.

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

The exact schema may change during implementation, but all detectors must use the same contract.

---

# 7. Definition of Done for Every Vulnerability Milestone

A vulnerability milestone is considered complete only when:

- [ ] The vulnerable scenario is confirmed in the laboratory.
- [ ] The detector can execute from the common engine.
- [ ] Safe test input/payload is implemented.
- [ ] Validation logic is implemented.
- [ ] Vulnerable configuration produces the expected finding.
- [ ] A negative/secure scenario is tested where practical.
- [ ] Evidence is captured.
- [ ] Severity is assigned.
- [ ] Confidence is assigned.
- [ ] CWE/OWASP/CVE mapping is added where applicable.
- [ ] Remediation guidance is included.
- [ ] Result follows the shared schema.
- [ ] Result is saved to PostgreSQL.
- [ ] Result is available through the backend API.
- [ ] Result can be viewed on the dashboard.
- [ ] Automated tests are added where practical.
- [ ] Manual reproduction steps are documented.
- [ ] Detector failure does not terminate the entire scan.
- [ ] The owning team member has reviewed and signed off their module.

---

# 8. Eight-Week Implementation Roadmap

> **Parallel rule for vulnerability weeks (Weeks 2–6):** each week, Sparsh builds one detector, Sunil builds another, and Nischal builds another — three detectors per week.

# Week 1 — Project Foundation, Architecture, Laboratory and Auth

## Objectives

Build the technical foundation (including the platform login system) required by every later milestone.

## Tasks

### Project Management

- [ ] Confirm final scope.
- [ ] Confirm the fifteen vulnerability categories.
- [ ] Confirm team responsibilities (per Section 2A).
- [ ] Create GitHub repository.
- [ ] Configure branch strategy.
- [ ] Configure issue/project board.
- [ ] Create coding standards.
- [ ] Create pull-request process.
- [ ] Create documentation structure.

### Development Environment

- [ ] Initialise Python/FastAPI backend.
- [ ] Configure `uv` package management.
- [ ] Initialise React + TypeScript frontend.
- [ ] Configure Tailwind CSS.
- [x] Configure PostgreSQL. — *Delivered on managed **Neon** Postgres (pooled `postgresql+asyncpg://` connection) rather than a local-only container; a local `postgres` container remains available behind an opt-in `local-db` Compose profile.*
- [ ] Add SQLAlchemy.
- [ ] Configure migrations.
- [ ] Add environment configuration.
- [ ] Add `.env.example`.
- [ ] Add logging framework.

### Authentication Foundation (Platform Login)

- [ ] Add `User` model and migration.
- [ ] Add password hashing and JWT utilities.
- [ ] Scaffold `/api/auth` router (login stub).
- [ ] Define role model (`ADMIN`, `ANALYST`, `VIEWER`).
- [ ] Seed initial admin account from environment.

### Laboratory Setup

- [ ] Deploy DVWA.
- [ ] Deploy OWASP Juice Shop.
- [ ] Deploy Metasploitable 2.
- [ ] Create local HTTPS/TLS test server.
- [ ] Place targets on isolated/private network.
- [ ] Seed test accounts.
- [ ] Seed files.
- [ ] Seed database objects.
- [ ] Create test JWT/session data where needed.
- [ ] Document target versions.

### Safety Controls

- [ ] Implement target allowlist design.
- [ ] Reject public/unapproved hosts.
- [ ] Configure scan timeout.
- [ ] Define request rate limits.
- [ ] Define harmless payload rules.
- [ ] Prevent destructive testing.
- [ ] Add scan logging/audit requirements.

### Architecture

- [ ] Define detector interface.
- [ ] Define scan context.
- [ ] Define result schema.
- [ ] Define evidence schema.
- [ ] Define database entities.
- [ ] Define validation status.
- [ ] Define remediation status.
- [ ] Define severity levels.
- [ ] Define confidence levels.

## Week 1 Milestone — M1: Scope, Architecture, Lab Foundation and Auth Scaffold

### Acceptance Criteria

- Repository is operational.
- Backend and frontend start locally.
- PostgreSQL connection works.
- Initial laboratory targets are reachable.
- Shared detector interface is documented.
- Database design (including `User`) is approved.
- Auth scaffold and initial admin account exist.
- Safety boundary is documented.

---

# Week 2 — Core Framework + Auth Completion + Vulnerabilities (Round 1)

**Parallel detectors this week:** Sparsh → SQL Injection · Sunil → Command Injection · Nischal → File Upload

## Platform Tasks

- [ ] Complete login/auth system (endpoints, protected routes, frontend login page, role enforcement, tests).
- [ ] Implement target model.
- [ ] Implement target API.
- [ ] Implement allowlist verification.
- [ ] Implement scan model.
- [ ] Implement scan API.
- [ ] Implement detector registry.
- [ ] Implement scan orchestrator.
- [ ] Implement common detector result model.
- [ ] Implement finding model.
- [ ] Implement evidence model.
- [ ] Add structured logging.
- [ ] Add detector exception isolation.

---

## Vulnerability Milestone V1 — SQL Injection · *Owner: Sparsh*

**Target:** DVWA  
**Risk:** Critical

### Implementation Tasks

- [ ] Identify controlled SQL injection endpoint.
- [ ] Establish normal baseline request.
- [ ] Implement controlled true-condition request.
- [ ] Implement controlled false-condition request.
- [ ] Compare response differences.
- [ ] Add safe timing confirmation where appropriate.
- [ ] Prevent destructive queries.
- [ ] Capture request/response evidence.
- [ ] Assign confidence based on validation strength.
- [ ] Map to CWE-89.
- [ ] Add remediation guidance.
- [ ] Add positive test.
- [ ] Add negative test where practical.
- [ ] Integrate result into API/database.

### Acceptance Criteria

The detector consistently identifies the seeded DVWA SQL injection scenario and provides reproducible evidence without changing or destroying application data.

---

## Vulnerability Milestone V2 — Command Injection · *Owner: Sunil*

**Target:** DVWA  
**Risk:** Critical

### Implementation Tasks

- [x] Identify command injection endpoint.
- [x] Establish baseline response.
- [x] Send harmless unique marker or controlled timing canary.
- [x] Confirm behavioural difference.
- [x] Prevent destructive operating-system commands.
- [x] Capture evidence.
- [x] Add severity/confidence.
- [x] Add CWE mapping.
- [x] Add remediation guidance.
- [x] Implement tests.
- [x] Integrate with shared schema.
- [x] *(Beyond original scope)* Optional OWASP ZAP active-scan cross-check — when `ScanContext.extra['use_zap']` is set, the manual finding is corroborated (or noted as unavailable) against ZAP's own result via `combine_with_zap()`, without changing the manual probe's own logic.

### Acceptance Criteria

The detector confirms command execution only through a harmless marker/timing condition and stores evidence in the shared finding structure.

---

## Vulnerability Milestone V3 — Unrestricted File Upload · *Owner: Nischal*

**Target:** DVWA  
**Risk:** Critical

### Implementation Tasks

- [ ] Identify upload endpoint.
- [ ] Prepare harmless test files.
- [ ] Test extension validation.
- [ ] Test MIME validation.
- [ ] Test extension/MIME mismatch.
- [ ] Verify whether uploaded file is stored.
- [ ] Verify whether uploaded file is publicly accessible.
- [ ] Never upload executable/destructive payload.
- [ ] Capture upload response and retrieval evidence.
- [ ] Assign severity/confidence.
- [ ] Add classification/remediation.
- [ ] Integrate into scanner.

### Acceptance Criteria

The detector can prove unsafe upload handling with harmless files and verify resulting accessibility.

---

## Week 2 Milestone — M2: Auth + Core Framework + First Three Detectors (3/15)

### Acceptance Criteria

- Login/authentication protects the platform.
- Core scan orchestration works.
- Findings persist to PostgreSQL.
- SQL Injection (Sparsh), Command Injection (Sunil), and File Upload (Nischal) work.
- A scan can execute multiple detectors without one detector failure terminating the scan.

---

# Week 3 — Vulnerabilities (Round 2) + Backend Integration

**Parallel detectors this week:** Sparsh → XSS · Sunil → Weak Authentication · Nischal → JWT / Session Security

## Vulnerability Milestone V4 — Cross-Site Scripting (XSS) · *Owner: Sparsh*

**Target:** DVWA / OWASP Juice Shop  
**Risk:** Medium–High

### Tasks

- [ ] Identify controlled reflected/stored XSS scenario.
- [ ] Generate unique harmless marker.
- [ ] Submit marker through target input.
- [ ] Use Playwright for browser-side verification.
- [ ] Confirm execution rather than reflection alone.
- [ ] Capture endpoint/input/evidence.
- [ ] Add severity/confidence.
- [ ] Add CWE mapping.
- [ ] Add remediation guidance.
- [ ] Add automated tests.
- [ ] Integrate detector.

### Acceptance Criteria

A finding is confirmed only when browser-side execution of the controlled marker is demonstrated.

---

## Vulnerability Milestone V5 — Weak Authentication Controls · *Owner: Sunil*

**Target:** Juice Shop / Metasploitable 2  
**Risk:** High

### Tasks

- [ ] Test controlled username enumeration.
- [ ] Compare login error behaviour.
- [ ] Check rate-limiting behaviour using strict safe limits.
- [ ] Check lockout behaviour.
- [ ] Test only approved default laboratory credentials.
- [ ] Do not implement general password cracking.
- [ ] Capture response/timing evidence.
- [ ] Add severity/confidence.
- [ ] Add CWE/remediation.
- [ ] Integrate detector.

### Acceptance Criteria

Weak authentication controls are demonstrated using synthetic accounts or approved laboratory default credentials without brute-forcing real users.

---

## Vulnerability Milestone V6 — Authentication / Session / JWT Weaknesses · *Owner: Nischal*

**Target:** OWASP Juice Shop  
**Risk:** High–Critical

### Tasks

- [ ] Obtain controlled laboratory JWT/session.
- [x] Parse JWT header and claims.
- [x] Check expiration claims.
- [x] Check important token properties.
- [ ] Submit malformed token.
- [ ] Submit expired test token where supported.
- [ ] Test controlled token modification.
- [ ] Verify invalid signatures are rejected.
- [x] Check session handling relevant to the target.
- [ ] Never use real credentials/tokens.
- [x] Capture claims and responses safely.
- [x] Mask sensitive values in logs.
- [x] Add severity/confidence.
- [x] Add CWE/remediation.
- [x] Integrate detector.

### Acceptance Criteria

The detector reports a finding only when controlled invalid authentication/session/token conditions are accepted or an explicitly defined weakness is demonstrated.

---

## Backend Tasks

- [ ] Create finding endpoints.
- [ ] Create evidence endpoints.
- [ ] Add scan-result retrieval.
- [ ] Add pagination.
- [ ] Add filtering by target.
- [ ] Add filtering by vulnerability.
- [ ] Add filtering by severity.
- [ ] Add validation-status filtering.

## Week 3 Milestone — M2B: Six Integrated Detectors (6/15)

### Acceptance Criteria

Six detectors (SQL Injection, Command Injection, File Upload, XSS, Weak Authentication, JWT/Session) produce structured findings, and their results are queryable using the authenticated backend API.

---

# Week 4 — Vulnerabilities (Round 3) + Dashboard MVP

**Parallel detectors this week:** Sparsh → IDOR · Sunil → Sensitive Files · Nischal → Path Traversal

## Vulnerability Milestone V7 — Broken Access Control / IDOR · *Owner: Sparsh*

**Target:** OWASP Juice Shop  
**Risk:** High–Critical

### Tasks

- [ ] Create/identify User A.
- [ ] Create/identify User B.
- [ ] Seed ownership-specific objects.
- [ ] Authenticate as User A.
- [ ] Request User A object.
- [ ] Request or modify User B object using User A session.
- [ ] Compare access behaviour.
- [ ] Verify unauthorised access/change.
- [ ] Capture object IDs and response evidence.
- [ ] Add severity/confidence.
- [ ] Add CWE/OWASP mapping.
- [ ] Add remediation.
- [ ] Integrate detector.

### Acceptance Criteria

The detector confirms broken object-level authorisation only when User A can access or modify data belonging to User B.

---

## Vulnerability Milestone V8 — Sensitive-File Exposure · *Owner: Sunil*

**Target:** Juice Shop / Metasploitable 2  
**Risk:** Medium–High

### Tasks

- [ ] Define approved sensitive-file candidate list.
- [ ] Check seeded backup files.
- [ ] Check controlled log files.
- [ ] Check configuration-file exposure.
- [ ] Check source-map exposure.
- [ ] Check repository metadata where applicable.
- [ ] Check directory listing.
- [ ] Do not retrieve unrelated personal information.
- [ ] Capture status/response evidence.
- [ ] Add severity/confidence.
- [ ] Add CWE/remediation.
- [ ] Integrate detector.

### Acceptance Criteria

The detector identifies only intentionally exposed/approved laboratory files and records evidence without collecting unnecessary data.

---

## Vulnerability Milestone V9 — Path Traversal / File Inclusion · *Owner: Nischal*

**Target:** DVWA  
**Risk:** High–Critical

### Tasks

- [ ] Create/identify harmless seeded canary file.
- [ ] Establish expected permitted path behaviour.
- [ ] Submit controlled traversal variants.
- [ ] Verify whether canary content is returned.
- [ ] Avoid reading real operating-system secrets.
- [ ] Capture request/response evidence.
- [ ] Assign severity/confidence.
- [ ] Add CWE mapping/remediation.
- [ ] Integrate detector.

### Acceptance Criteria

The detector confirms traversal only if content from the controlled file outside the intended directory is returned.

---

## Dashboard MVP Tasks

- [ ] Dashboard layout (behind login).
- [ ] Total findings card.
- [ ] Severity distribution.
- [ ] Findings by vulnerability category.
- [ ] Findings by target.
- [ ] Recent scans.
- [ ] Scan status.
- [ ] Findings table.
- [ ] Finding-detail page.
- [ ] Evidence presentation.
- [ ] Confidence display.
- [ ] Filtering/search.

## Week 4 Milestone — M3A: Nine Integrated Detectors + Dashboard MVP (9/15)

### Acceptance Criteria

- Nine vulnerability modules work end-to-end.
- Results pass through detector → API → database → dashboard.
- Dashboard MVP can display real detector findings behind authentication.

---

# Week 5 — Vulnerabilities (Round 4) + Dashboard Completion

**Parallel detectors this week:** Sparsh → SSRF · Sunil → Vulnerable Services · Nischal → CSRF

## Vulnerability Milestone V10 — Server-Side Request Forgery (SSRF) · *Owner: Sparsh*

**Target:** OWASP Juice Shop  
**Risk:** High

### Tasks

- [ ] Identify server-side URL-fetching functionality.
- [ ] Configure controlled callback/internal endpoint.
- [ ] Submit controlled URL.
- [ ] Verify whether the application server makes the request.
- [ ] Use only owned/private endpoints.
- [ ] Capture callback/request evidence.
- [ ] Add severity/confidence.
- [ ] Add CWE/remediation.
- [ ] Integrate detector.

### Acceptance Criteria

The detector confirms SSRF only when the controlled callback/internal service observes a request attributable to the target.

---

## Vulnerability Milestone V11 — Known Vulnerable Services · *Owner: Sunil*

**Target:** Metasploitable 2  
**Risk:** CVE-dependent

### Tasks

- [ ] Perform controlled service discovery.
- [ ] Record host.
- [ ] Record port.
- [ ] Identify service.
- [ ] Identify version/banner.
- [ ] Normalise service information.
- [ ] Map product/version to CPE where practical.
- [ ] Correlate with CVE information.
- [ ] Store CVE ID.
- [ ] Store CVSS score where available.
- [ ] Preserve evidence/source.
- [ ] Avoid automatic exploitation.
- [ ] Integrate detector.

### Acceptance Criteria

Known laboratory service versions can be identified and associated with appropriate vulnerability references without exploitation.

---

## Vulnerability Milestone V12 — Cross-Site Request Forgery (CSRF) · *Owner: Nischal*

**Target:** DVWA / Juice Shop where applicable  
**Risk:** Medium–High

### Tasks

- [ ] Identify controlled state-changing operation.
- [ ] Inspect anti-CSRF token presence.
- [ ] Inspect SameSite cookie configuration.
- [ ] Evaluate origin/referer validation where applicable.
- [ ] Attempt controlled request without expected protection.
- [ ] Confirm whether state change occurs.
- [ ] Reset seeded state after testing.
- [ ] Capture evidence.
- [ ] Add severity/confidence.
- [ ] Add CWE/remediation.
- [ ] Integrate detector.

### Acceptance Criteria

The detector demonstrates whether a controlled state-changing operation succeeds without expected CSRF protections.

---

## Dashboard / Platform Completion Tasks

- [ ] Complete dashboard core views.
- [ ] Implement severity filtering.
- [ ] Implement confidence filtering.
- [ ] Implement target filtering.
- [ ] Implement vulnerability filtering.
- [ ] Add scan history.
- [ ] Add new/recurring/remediated comparison logic.
- [ ] Add finding remediation status.
- [ ] Add finding status update API.
- [ ] Add CWE display.
- [ ] Add CVE display.
- [ ] Add CVSS display.
- [ ] Add OWASP category display.

## Week 5 Milestone — M3: Twelve Integrated Detectors + Full Dashboard (12/15)

### Acceptance Criteria

- Twelve detectors work end-to-end.
- Dashboard supports severity/confidence/target/vulnerability filtering, scan history, and remediation status.

---

# Week 6 — Vulnerabilities (Round 5) + Integration, Reporting, Containers, CI/CD

**Parallel detectors this week:** Sparsh → XXE · Sunil → Weak TLS · Nischal → Security Misconfiguration

## Vulnerability Milestone V13 — XML External Entity (XXE) · *Owner: Sparsh*

**Target:** Juice Shop / controlled XML endpoint  
**Risk:** High–Critical

### Tasks

- [ ] Identify or configure controlled XML endpoint.
- [ ] Create harmless seeded local resource.
- [ ] Create controlled external entity reference.
- [ ] Submit XML.
- [ ] Verify whether entity is processed.
- [ ] Avoid accessing system-sensitive files.
- [ ] Capture safe evidence.
- [ ] Add severity/confidence.
- [ ] Add CWE/remediation.
- [ ] Integrate detector.

### Acceptance Criteria

The detector confirms XXE only when processing of a harmless controlled external entity/resource is demonstrated.

---

## Vulnerability Milestone V14 — Weak TLS Configuration · *Owner: Sunil*

**Target:** Local HTTPS test service  
**Risk:** Medium–High

### Tasks

- [ ] Configure controlled HTTPS service.
- [ ] Create known certificate scenarios.
- [ ] Test supported TLS protocol versions.
- [ ] Test configured cipher suites.
- [ ] Inspect certificate validity.
- [ ] Inspect certificate expiry.
- [ ] Inspect hostname properties where applicable.
- [ ] Identify obsolete protocols/ciphers.
- [ ] Capture TLS evidence.
- [ ] Add severity/confidence.
- [ ] Add CWE/remediation where applicable.
- [ ] Integrate detector.

### Acceptance Criteria

The detector correctly identifies intentionally configured weak TLS characteristics in the local test service.

---

## Vulnerability Milestone V15 — Security Misconfiguration · *Owner: Nischal*

**Target:** All laboratory targets  
**Risk:** Medium–High

### Tasks

- [x] Check security headers.
- [x] Check cookie security attributes.
- [ ] Check exposed directory listing.
- [ ] Check default pages.
- [ ] Check debug/error-information leakage.
- [ ] Check obviously unsafe exposed services.
- [x] Define each check separately.
- [x] Avoid reporting purely informational items as high severity.
- [x] Store individual evidence.
- [x] Add confidence/remediation.
- [x] Integrate detector.

### Acceptance Criteria

The detector reports clearly defined configuration weaknesses with sufficient evidence and appropriate severity.

---

## Integration, Reporting, Containers and CI/CD (shared)

### Backend Integration

- [ ] Finalise scan orchestration.
- [ ] Finalise detector registry.
- [ ] Add per-detector timeout.
- [ ] Add scan cancellation where appropriate.
- [ ] Add partial scan handling.
- [ ] Finalise error capture.
- [ ] Add audit records (including authenticated user).
- [ ] Add database indexes.
- [ ] Validate migrations.
- [ ] Add API documentation.

### Reporting

> **Delivered format differs from the original plan:** rather than a backend-rendered HTML/PDF report, findings export is generated **client-side** in the dashboard (`frontend/src/lib/report.ts`) directly from the findings already loaded on screen — as CSV and a Word-openable (`.doc`) document. There is no `POST /reports/{scan_id}` backend endpoint.

- [x] Create report template. — *`COLUMN_LABELS`/`COLUMNS` in `report.ts`.*
- [ ] Add target summary. — *Not included; export is a per-finding table, not a target-level rollup.*
- [ ] Add scan information. — *Not included at the report level (available separately via Scan Detail).*
- [ ] Add severity summary. — *Not included; dashboard charts cover this instead.*
- [x] Add detailed findings.
- [x] Add evidence summary. — *`evidence_summary` column.*
- [x] Add CWE/CVE/CVSS references.
- [ ] Add remediation. — *Not currently a report column; visible on the Finding Detail page.*
- [ ] Export HTML. — *Superseded by CSV/DOC export below.*
- [ ] Export PDF if practical within schedule. — *Superseded by CSV/DOC export below.*
- [x] Export CSV.
- [x] Export Word-openable document (`.doc`).

### Dockerisation

- [ ] Backend Dockerfile.
- [ ] Frontend Dockerfile.
- [ ] PostgreSQL service.
- [ ] Docker Compose.
- [ ] Environment variables.
- [ ] Persistent database volume.
- [ ] Health checks.
- [ ] Internal/private laboratory networking.
- [ ] Reproducible setup documentation.

### CI/CD

GitHub Actions should perform at minimum:

```text
Push / Pull Request
        |
        v
Install Dependencies
        |
        v
Lint / Static Checks
        |
        v
Unit Tests (incl. auth)
        |
        v
Backend Tests
        |
        v
Frontend Build
        |
        v
Docker Build
        |
        v
Integration / Release Checks
```

Tasks:

- [ ] Backend lint.
- [ ] Backend unit tests.
- [ ] Frontend lint/build.
- [ ] Detector tests.
- [ ] Auth tests.
- [ ] API tests.
- [ ] Docker build.
- [ ] Prevent secrets from being committed.
- [ ] Create release candidate workflow.

## Week 6 Milestone — M4/M5A: All 15 Detectors + Integrated, Containerised System (15/15)

### Acceptance Criteria

- All fifteen vulnerability detectors are implemented and use the common framework.
- Findings are persisted and shown on the dashboard behind login.
- A new environment can start the platform through documented container instructions and execute an end-to-end scan through the dashboard/backend.

### Feature Freeze

After this milestone, avoid adding major new features. Weeks 7–8 focus on validation, documentation, performance, defects, and delivery.

---

# Week 7 — Detector Validation, Accuracy and Performance

This week is primarily evaluation rather than new feature development. Each member validates their own five detectors, and the team cross-reviews.

# 9. Detector Validation Matrix

| # | Detector | Owner | Vulnerable Test | Secure/Negative Test | Repeat Test | Evidence Review | Result |
|---|---|---|---|---|---|---|---|
| 1 | SQL Injection | Sparsh | ☐ | ☐ | ☐ | ☐ | Pending |
| 2 | Command Injection | Sunil | ☐ | ☐ | ☐ | ☐ | Pending |
| 3 | File Upload | Nischal | ☐ | ☐ | ☐ | ☐ | Pending |
| 4 | XSS | Sparsh | ☐ | ☐ | ☐ | ☐ | Pending |
| 5 | Weak Authentication | Sunil | ☐ | ☐ | ☐ | ☐ | Pending |
| 6 | JWT/Session | Nischal | ☐ | ☐ | ☐ | ☐ | Pending |
| 7 | IDOR | Sparsh | ☐ | ☐ | ☐ | ☐ | Pending |
| 8 | Sensitive Files | Sunil | ☐ | ☐ | ☐ | ☐ | Pending |
| 9 | Path Traversal | Nischal | ☐ | ☐ | ☐ | ☐ | Pending |
| 10 | SSRF | Sparsh | ☐ | ☐ | ☐ | ☐ | Pending |
| 11 | Vulnerable Services | Sunil | ☐ | ☐ | ☐ | ☐ | Pending |
| 12 | CSRF | Nischal | ☐ | ☐ | ☐ | ☐ | Pending |
| 13 | XXE | Sparsh | ☐ | ☐ | ☐ | ☐ | Pending |
| 14 | Weak TLS | Sunil | ☐ | ☐ | ☐ | ☐ | Pending |
| 15 | Misconfiguration | Nischal | ☐ | ☐ | ☐ | ☐ | Pending |
| — | Platform Auth/Login | Shared | ☐ | ☐ | ☐ | ☐ | Pending |

---

# 10. Evaluation Metrics

## Detection Rate

```text
Detection Rate =
Correctly Detected Known Vulnerabilities
---------------------------------------- × 100
Total Known Vulnerabilities
```

## False-Positive Rate

Measure findings that cannot be manually reproduced or that also appear incorrectly against secure/negative configurations.

## False-Negative Rate

Measure seeded vulnerabilities that the relevant detector fails to detect.

## Repeatability

Execute the same detector multiple times against an unchanged target and compare outcomes.

## Scan Duration

Record:

- individual detector duration
- total scan duration
- slowest detector
- timeout/error rate

The demonstration scan profile should aim to complete within approximately **30 minutes** under normal laboratory conditions.

## Evidence Quality

Review whether each finding contains enough information to reproduce and understand the result.

## Dashboard Usability

A reviewer should be able to identify:

- highest-risk findings
- affected target
- vulnerability type
- evidence
- recommended remediation

without needing to inspect raw logs.

---

# 11. Week 7 Tasks

- [ ] Test all 15 detectors (each owner leads their own; peer cross-check).
- [ ] Test platform auth (valid/invalid login, expired token, role denial).
- [ ] Execute repeated scans.
- [ ] Execute negative/secure tests where possible.
- [ ] Calculate detection rate.
- [ ] Calculate false-positive rate.
- [ ] Calculate false-negative rate.
- [ ] Measure detector durations.
- [ ] Measure complete scan duration.
- [ ] Review evidence quality.
- [ ] Correct high-priority bugs.
- [ ] Correct detector inconsistencies.
- [ ] Correct dashboard defects.
- [ ] Verify report output.
- [ ] Verify Docker clean deployment.
- [ ] Verify CI pipeline.
- [ ] Finalise release candidate.
- [ ] Capture screenshots/results for report.

## Week 7 Milestone — M5: Validated Release Candidate

### Acceptance Criteria

- All 15 detector implementations (+ auth) have validation results.
- Critical defects are resolved.
- Evaluation metrics are available.
- CI/CD passes.
- Container deployment works.
- Dashboard works with real findings behind login.
- Release candidate is ready for final demonstration preparation.

---

# Week 8 — Final Delivery

## Final Software Tasks

- [ ] Freeze release.
- [ ] Create release tag.
- [ ] Clean repository.
- [ ] Remove temporary files.
- [ ] Verify no credentials/secrets exist in repository.
- [ ] Verify `.env.example`.
- [ ] Verify fresh installation.
- [ ] Verify database migrations.
- [ ] Verify all URLs and configuration.
- [ ] Verify demo accounts (including at least one admin login).
- [ ] Verify demo target state.

## Technical Documentation

- [ ] README.
- [ ] Installation guide.
- [ ] Configuration guide.
- [ ] Architecture documentation.
- [ ] Database documentation.
- [ ] API documentation (including `/api/auth`).
- [ ] Detector documentation (per owner).
- [ ] Testing guide.
- [ ] Safety/ethical controls.
- [ ] Troubleshooting guide.

## Academic Report

Suggested evidence to include:

- architecture (including auth/login)
- database design
- detector framework
- explanation of each detector and its owner
- screenshots
- sample findings
- testing methodology
- evaluation metrics
- limitations
- risks
- ethical considerations
- future enhancements

## Demonstration Preparation

Prepare a deterministic demo rather than relying on an uncontrolled live setup.

Suggested sequence:

```text
1. Log in to VulnVista
2. Open VulnVista dashboard
3. Show approved targets
4. Start a selected scan
5. Show scan progress/status
6. Show several detected vulnerabilities
7. Open one finding
8. Explain evidence and confidence
9. Show CWE/CVE/CVSS data where applicable
10. Change remediation status
11. Show scan history/comparison
12. Export report
13. Briefly show CI/CD and Docker deployment
```

It is not necessary to run all fifteen detectors live during a short presentation. All fifteen should be demonstrable and have recorded validation results.

## Presentation

- [ ] Problem.
- [ ] Proposed solution.
- [ ] Architecture (including login/auth).
- [ ] Detection engine.
- [ ] 15 vulnerabilities and their owners.
- [ ] Validation approach.
- [ ] Dashboard.
- [ ] Results.
- [ ] Evaluation.
- [ ] CI/CD/deployment.
- [ ] Limitations.
- [ ] Future enhancements.

## Week 8 Milestone — M6: Final Delivery

### Acceptance Criteria

The team submits:

- working VulnVista prototype (with login/auth)
- all fifteen detector modules
- source code
- container configuration
- CI/CD configuration
- technical documentation
- academic report
- evaluation results
- presentation
- final demonstration

---

# 12. Complete Milestone Register

| Milestone | Target | Owners (parallel) | Expected Outcome |
|---|---|---|---|
| M1 | End Week 1 | All | Scope, architecture, lab foundation + auth scaffold |
| V1 | Week 2 | Sparsh | SQL injection detector |
| V2 | Week 2 | Sunil | Command injection detector |
| V3 | Week 2 | Nischal | File-upload detector |
| M2 | End Week 2 | All | Auth complete + core framework + first 3 detectors (3/15) |
| V4 | Week 3 | Sparsh | XSS detector |
| V5 | Week 3 | Sunil | Weak-authentication detector |
| V6 | Week 3 | Nischal | JWT/session detector |
| M2B | End Week 3 | All | Six integrated detectors (6/15) |
| V7 | Week 4 | Sparsh | IDOR/broken access-control detector |
| V8 | Week 4 | Sunil | Sensitive-file exposure detector |
| V9 | Week 4 | Nischal | Path traversal detector |
| M3A | End Week 4 | All | Nine integrated detectors + dashboard MVP (9/15) |
| V10 | Week 5 | Sparsh | SSRF detector |
| V11 | Week 5 | Sunil | Known vulnerable-service detector |
| V12 | Week 5 | Nischal | CSRF detector |
| M3 | End Week 5 | All | Twelve integrated detectors + full dashboard (12/15) |
| V13 | Week 6 | Sparsh | XXE detector |
| V14 | Week 6 | Sunil | Weak-TLS detector |
| V15 | Week 6 | Nischal | Security-misconfiguration detector |
| M4/M5A | End Week 6 | All | All 15 detectors + integrated/containerised system (15/15) |
| M5 | End Week 7 | All | Validated release candidate |
| M6 | End Week 8 | All | Final prototype, report and presentation |

---

# 13. Milestone Dependency Flow

```text
M1 Foundation (+ Auth/Login)
 |
 +--> Detector Interface
 |       |
 |       |   (each row below = one parallel week: Sparsh / Sunil / Nischal)
 |       +--> Week 2: SQL Injection / Command Injection / File Upload
 |       +--> Week 3: XSS / Weak Authentication / JWT-Session
 |       +--> Week 4: IDOR / Sensitive Files / Path Traversal
 |       +--> Week 5: SSRF / Vulnerable Services / CSRF
 |       +--> Week 6: XXE / Weak TLS / Misconfiguration
 |
 +--> Auth / Login System
 |
 +--> Database
 |
 +--> Scan Orchestrator
 |
 +--> Backend API
 |
 +--> Dashboard
 |
 +--> Reporting
 |
 +--> Docker / CI-CD
 |
 +--> Validation
 |
 +--> Final Delivery
```

---

# 14. Team Workstreams and Parallel Ownership

Every member owns five detectors (Section 2A) and, in each vulnerability week, works one detector in parallel with the other two. Platform work is layered on top and shared, with a lead area per member.

## Detector Ownership

- **Nischal:** File Upload, JWT/Session, Path Traversal, CSRF, Security Misconfiguration.
- **Sparsh:** SQL Injection, XSS, IDOR, SSRF, XXE.
- **Sunil:** Command Injection, Weak Authentication, Sensitive Files, Vulnerable Services, Weak TLS.

## Suggested Platform Lead Areas

These are leads, not silos — all three collaborate across areas.

### Workstream A — Cybersecurity / Detector Development (all three)

- laboratory target configuration
- detector design and safe payloads/tests
- evidence collection and validation rules
- security classifications and detector testing

### Workstream B — Backend / Auth / Cloud / CI-CD

- FastAPI, SQLAlchemy, PostgreSQL
- **login/authentication and access control**
- scanner orchestration, API
- Docker, automated tests, CI/CD, deployment

### Workstream C — Frontend / Data Visualisation

- React/TypeScript
- login page and protected routes
- dashboard, scan status, findings table, charts
- finding detail, evidence presentation, scan history
- remediation workflow, reporting presentation

## Shared Responsibilities

All team members participate in: architecture decisions, integration, validation, documentation, report writing, presentation, and the live demonstration.

---

# 15. API Implementation Checklist

Potential core API groups:

```text
/api/auth
/api/targets
/api/scans
/api/detectors
/api/findings
/api/evidence
/api/reports
/api/dashboard
```

Example operations:

```text
POST   /auth/login
POST   /auth/logout
GET    /auth/me
POST   /auth/users            (admin only)

POST   /targets
GET    /targets
GET    /targets/{id}

POST   /scans
GET    /scans
GET    /scans/{id}
GET    /scans/{id}/findings

GET    /detectors

GET    /findings
GET    /findings/{id}
PATCH  /findings/{id}/status

GET    /dashboard/summary
GET    /dashboard/severity
GET    /dashboard/categories

POST   /reports/{scan_id}
```

All non-public endpoints require a valid authentication token. The final endpoint design can be adapted during development.

---

# 16. Dashboard Implementation Checklist

## Login / Access

- [ ] Login page.
- [ ] Token storage/refresh handling.
- [ ] Protected-route wrapper.
- [ ] Role-based UI (hide privileged actions from viewers).
- [ ] Logout.

## Main Dashboard

- [ ] Total scans.
- [ ] Total findings.
- [ ] Critical count.
- [ ] High count.
- [ ] Medium count.
- [ ] Low count.
- [ ] Severity chart.
- [ ] Vulnerability-category chart.
- [ ] Target distribution.
- [ ] Recent scans.
- [ ] Recent critical findings.

## Targets Page

- [ ] Target list.
- [ ] Approved status.
- [ ] Target type.
- [ ] Previous scans.
- [ ] Add approved target.
- [ ] Start scan.

## New Scan Page

- [ ] Select target.
- [ ] Select detectors.
- [ ] Select scan profile.
- [ ] Show safety boundary.
- [ ] Start scan.

## Scan Detail

- [ ] Status.
- [ ] Start/end time.
- [ ] Duration.
- [ ] Detectors executed.
- [ ] Detector errors.
- [ ] Findings.
- [ ] Severity summary.

## Finding Detail

- [ ] Vulnerability.
- [ ] Severity.
- [ ] Confidence.
- [ ] Validation status.
- [ ] Target.
- [ ] Endpoint/parameter.
- [ ] Technical description.
- [ ] Evidence.
- [ ] CWE.
- [ ] CVE/CVSS where applicable.
- [ ] OWASP category where applicable.
- [ ] Remediation.
- [ ] Finding status.
- [ ] Status update.

## History

- [ ] Previous scans.
- [ ] Compare scans.
- [ ] New findings.
- [ ] Recurring findings.
- [ ] Remediated findings.

---

# 17. Testing Strategy

## Unit Testing

Test:

- validation helpers
- severity/confidence mapping
- parsing
- response-comparison logic
- JWT parsing
- TLS parsing
- service-version parsing
- finding creation
- **password hashing and platform token verification**

## Auth Tests

- valid login returns a token
- invalid credentials are rejected
- expired/invalid token is rejected
- role-restricted endpoints deny lower roles
- protected routes reject anonymous requests

## Detector Tests

Each detector should have:

- positive fixture/test
- negative fixture/test where practical
- timeout behaviour
- target/network-error handling

## API Tests

Test:

- authenticated target creation
- target rejection
- scan creation
- findings retrieval
- filtering
- finding-status updates
- report generation

## Integration Tests

Test:

```text
Login
  ↓
Target
  ↓
Scan API
  ↓
Detector
  ↓
Finding
  ↓
Database
  ↓
API
  ↓
Dashboard
```

## Manual Validation

Every confirmed detector must also have documented manual reproduction during evaluation.

---

# 18. Security and Ethical Controls Checklist

- [ ] Only intentionally vulnerable or team-owned targets.
- [ ] Private laboratory network.
- [ ] Target allowlisting.
- [ ] Platform protected by authentication/login.
- [ ] Passwords stored hashed; no plaintext secrets.
- [ ] No arbitrary public target scanning.
- [ ] Synthetic user information only.
- [ ] Synthetic credentials.
- [ ] Synthetic tokens.
- [ ] Harmless files.
- [ ] Harmless command markers.
- [ ] Controlled timing tests.
- [ ] No destructive SQL.
- [ ] No malware.
- [ ] No persistence.
- [ ] No denial-of-service.
- [ ] No automatic exploitation to obtain system control.
- [ ] No real-user password cracking.
- [ ] Request-rate controls.
- [ ] Timeout controls.
- [ ] Scan audit logging (records authenticated initiator).
- [ ] Secrets excluded from Git.
- [ ] Final demo stays inside contained environment.

---

# 19. Risk-Control Gates

## End of Week 2

If the shared detector framework or auth is unstable:

**Stop adding new detector complexity and stabilise the common interface and login first.**

## End of Week 3

If six detectors are not integrated:

**Simplify evidence/UI features temporarily and prioritise detector completion — each member protects their own weekly detector.**

## End of Week 4

If fewer than nine detectors work:

**Re-balance: any member ahead helps a member who is behind, without breaking the one-detector-per-person-per-week rhythm where possible.**

## End of Week 5

If fewer than twelve detectors work:

**Allocate additional shared capacity to detector completion before starting Week 6 integration.**

## End of Week 6

**Feature freeze.** All fifteen detectors and the login system should exist. No unnecessary major features after this point.

## Week 7

Validation and defects only unless a missing feature blocks project acceptance.

## Week 8

Delivery/documentation/demo only.

---

# 20. Final Definition of Project Done

The project is complete when:

- [ ] DVWA is available in the isolated lab.
- [ ] OWASP Juice Shop is available.
- [ ] Metasploitable 2 is available.
- [ ] Local TLS test service is available.
- [ ] Login/authentication protects the platform.
- [ ] Role-based access control works.
- [ ] Target allowlisting works.
- [ ] Scan management works.
- [ ] SQL injection detector works. *(Sparsh)*
- [ ] Command injection detector works. *(Sunil)*
- [ ] File-upload detector works. *(Nischal)*
- [ ] XSS detector works. *(Sparsh)*
- [ ] Weak-authentication detector works. *(Sunil)*
- [x] JWT/session detector works. *(Nischal)*
- [ ] IDOR detector works. *(Sparsh)*
- [ ] Sensitive-file exposure detector works. *(Sunil)*
- [ ] Path traversal detector works. *(Nischal)*
- [ ] SSRF detector works. *(Sparsh)*
- [ ] Known vulnerable-services detector works. *(Sunil)*
- [ ] CSRF detector works. *(Nischal)*
- [ ] XXE detector works. *(Sparsh)*
- [ ] Weak-TLS detector works. *(Sunil)*
- [x] Security-misconfiguration detector works. *(Nischal)*
- [ ] All detector outputs use a common schema.
- [ ] Findings are stored in PostgreSQL.
- [ ] Evidence is retained.
- [ ] Severity/confidence are stored.
- [ ] CWE/CVE/CVSS/OWASP information is supported where applicable.
- [ ] Dashboard presents severity/category/target information.
- [ ] Detailed finding view works.
- [ ] Scan history works.
- [ ] Finding remediation status works.
- [ ] Report export works.
- [ ] Docker deployment works.
- [ ] CI/CD works.
- [ ] Detector failures are isolated.
- [ ] Evaluation metrics are calculated.
- [ ] Documentation is complete.
- [ ] Academic report is complete.
- [ ] Presentation is complete.
- [ ] Final demonstration is rehearsed.
- [ ] Final submission is complete.

---

# 21. Future Enhancement Boundary

The eight-week implementation should **not** expand into a general-purpose scanner integration framework.

After the core project is completed, VulnVista may support plugins/adapters for external tools such as:

- Nmap
- OWASP ZAP
- Nikto
- Trivy
- Nuclei

A future plugin could:

```text
External Security Tool
       |
       v
VulnVista Adapter
       |
       +--> Preserve Original Tool Output
       |
       +--> Normalise Findings
       |
       v
Shared VulnVista Finding Schema
       |
       v
Dashboard / Reports / History
```

For example:

- Nmap XML could contribute hosts, ports, services, and version information.
- OWASP ZAP API output could contribute alerts, URLs, parameters, evidence, confidence, and risk information.
- Correlation rules could later reduce duplicate findings from multiple sources.

This plugin architecture remains outside the core eight-week implementation unless all mandatory deliverables are completed early.

---

# 22. Recommended Implementation Priority

When time becomes constrained, use this order:

```text
1. Safe laboratory
2. Login / authentication system
3. Shared detector interface
4. Database schema
5. Week 2 trio: SQL Injection, Command Injection, File Upload
6. Week 3 trio: XSS, Weak Authentication, JWT/Session
7. Week 4 trio: IDOR, Sensitive Files, Path Traversal
8. Week 5 trio: SSRF, Vulnerable Services, CSRF
9. Week 6 trio: XXE, Weak TLS, Misconfiguration
10. Backend integration
11. Dashboard
12. History/remediation
13. Reporting
14. Docker/CI-CD
15. Validation
16. Documentation/demo
```

Within each trio, Sparsh, Sunil, and Nischal each protect their assigned detector so no single detector is dropped. The core academic value should remain **repeatable detection + explicit validation + structured evidence**, rather than adding many secondary features that cannot be tested properly within eight weeks.

---

# 23. Weekly Completion Summary

## Week 1
**Foundation + auth scaffold complete**

## Week 2 — 3/15
- Sparsh: SQL Injection
- Sunil: Command Injection
- Nischal: File Upload
- *(Platform login/auth completed)*

## Week 3 — 6/15
- Sparsh: XSS
- Sunil: Weak Authentication
- Nischal: JWT / Session Security

## Week 4 — 9/15
- Sparsh: IDOR
- Sunil: Sensitive Files
- Nischal: Path Traversal
- *(Dashboard MVP)*

## Week 5 — 12/15
- Sparsh: SSRF
- Sunil: Vulnerable Services
- Nischal: CSRF
- *(Full dashboard)*

## Week 6 — 15/15
- Sparsh: XXE
- Sunil: Weak TLS
- Nischal: Security Misconfiguration
- *(Integration, reporting, Docker, CI/CD)*

## Week 7
**Validated release candidate**

## Week 8
**Final submission and demonstration**

---

# 24. Final Delivery Target

At the end of Week 8, VulnVista should demonstrate the following complete lifecycle:

```text
Login (Authenticated User)
      ↓
Approved Target
      ↓
Select Vulnerability Modules
      ↓
Run Scan
      ↓
Detect Vulnerability
      ↓
Validate Finding
      ↓
Collect Evidence
      ↓
Assign Severity + Confidence
      ↓
Map Security Classification
      ↓
Store in PostgreSQL
      ↓
Display in Dashboard
      ↓
Review / Update Remediation Status
      ↓
Re-scan
      ↓
Compare History
      ↓
Generate Report
```

This lifecycle is the central implementation goal of VulnVista.
