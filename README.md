# VulnVista

> A controlled vulnerability-assessment platform for an isolated academic lab: a modular Python detection engine, FastAPI backend, PostgreSQL persistence, and a React/TypeScript dashboard covering fifteen vulnerability categories.

VulnVista detects, validates, stores, prioritises, and presents findings from intentionally vulnerable laboratory systems. It is being developed by **Group 7** for the **NIT6150 Advanced Project**. Unlike an orchestration layer around third-party scanners, each vulnerability category is checked by a purpose-built Python detector with its own safe test payload and validation logic — see [VulnVista_IMPLEMENTATION_PLAN.md](VulnVista_IMPLEMENTATION_PLAN.md) for the full eight-week roadmap and design detail.

> [!CAUTION]
> VulnVista is intended only for deliberately vulnerable applications in an isolated, pre-approved lab (DVWA, OWASP Juice Shop, Metasploitable2, a local TLS test service). Never use it to scan public, production, or third-party systems without explicit written authorization.

![VulnVista security posture dashboard showing open findings, severity distribution, scan outcomes, and detector coverage](docs/screenshots/vulnvista-dashboard.jpg)

## Milestone tracker

Full per-vulnerability checklists live in the [implementation plan](VulnVista_IMPLEMENTATION_PLAN.md#8-eight-week-implementation-roadmap). Summary:

| Milestone        | Target | Outcome                                                                | Status      |
| ---------------- | ------ | ---------------------------------------------------------------------- | ----------- |
| M1               | Week 1 | Scope, architecture, and lab foundation                                | ✅ Complete |
| V1–V3 + M2       | Week 2 | Core scan framework + SQL injection, command injection, file upload    | ✅ Complete |
| V4–V6 + M2B      | Week 3 | + XSS, weak authentication, JWT/session                                | ✅ Complete |
| V7–V9 + M3A      | Week 4 | + IDOR, sensitive files, path traversal; dashboard MVP                 | ✅ Complete |
| V10–V12 + M3     | Week 5 | + SSRF, vulnerable services, CSRF; full dashboard workflows            | ✅ Complete |
| V13–V15 + M4/M5A | Week 6 | + XXE, weak TLS, security misconfiguration; integration, Docker, CI/CD | ✅ Complete |
| M5               | Week 7 | Detector validation, accuracy checks, release-candidate hardening      | ✅ Complete |
| M6               | Week 8 | Final delivery, report, demonstration                                  | ✅ Complete |

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

| Target                 | Role                                          | Setup                                                                                      |
| ---------------------- | --------------------------------------------- | ------------------------------------------------------------------------------------------ |
| DVWA                   | Adjustable-difficulty vulnerability exercises | [lab/docker-compose.yml](lab/docker-compose.yml)                                           |
| OWASP Juice Shop       | Modern Node.js app covering the OWASP Top 10  | [lab/docker-compose.yml](lab/docker-compose.yml)                                           |
| Metasploitable2        | Known-vulnerable service catalogue            | [lab/docker-compose.yml](lab/docker-compose.yml) community image with mapped service ports |
| Local TLS test service | Weak TLS/certificate scenarios                | [lab/tls-test/](lab/tls-test/) via [lab/docker-compose.yml](lab/docker-compose.yml)        |

All targets run on an isolated `vulnvista_net` Docker network with no route to production infrastructure. See [lab/README.md](lab/README.md) for URLs, default credentials, and safety controls.

## Vulnerability categories

VulnVista implements the following fifteen categories. Each entry explains the weakness, the test performed by the current implementation, the rule used to classify the result, and what that evidence establishes. The numbering below follows this catalogue; milestone V-numbers follow the implementation roadmap.

| # | Category | # | Category |
| --- | --- | --- | --- |
| 1 | [SQL Injection](#1-sql-injection) | 9 | [Weak Authentication Controls](#9-weak-authentication-controls) |
| 2 | [Command Injection](#2-command-injection) | 10 | [Server-Side Request Forgery](#10-server-side-request-forgery-ssrf) |
| 3 | [Cross-Site Scripting](#3-cross-site-scripting-xss) | 11 | [XML External Entity](#11-xml-external-entity-xxe) |
| 4 | [Unrestricted File Upload](#4-unrestricted-file-upload) | 12 | [Sensitive-File Exposure](#12-sensitive-file-exposure) |
| 5 | [Path Traversal / File Inclusion](#5-path-traversal--file-inclusion) | 13 | [Known Vulnerable Services](#13-known-vulnerable-services) |
| 6 | [Cross-Site Request Forgery](#6-cross-site-request-forgery-csrf) | 14 | [Security Misconfiguration](#14-security-misconfiguration) |
| 7 | [Broken Access Control / IDOR](#7-broken-access-control--idor) | 15 | [Weak TLS Configuration](#15-weak-tls-configuration) |
| 8 | [Authentication / Session / JWT Weaknesses](#8-authentication--session--jwt-weaknesses) | | |

### How detection and classification work

Every detector implements the [BaseDetector contract](backend/app/scanners/base.py): `check()` collects observations, an optional `validate()` performs secondary validation, and `build_finding()` maps the result onto the shared finding schema. The [detector registry](backend/app/scanners/__init__.py) defines the modules available to scan profiles. Many modules separate their decision rules into a `classify()` function so the verdict can be tested independently of network requests.

A **baseline** is the target's normal response used for comparison. A **canary** is a harmless, recognisable test marker. A **callback** is a request received by a controlled listener, providing evidence of a request made by the target.

| Result field | Interpretation |
| --- | --- |
| `validation_status: CONFIRMED` | The detector's implemented positive rule was satisfied. The strength and scope of that rule vary by category. |
| `validation_status: SUSPECTED` | A possible weakness was observed, but stronger confirmation is missing. |
| `validation_status: NOT_DETECTED` | The tests performed did not meet the detector's positive criteria. This is not a guarantee that the target is secure. |
| `validation_status: INCONCLUSIVE` | Available observations cannot support a reliable verdict. |
| `validation_status: ERROR` | The detector could not complete its assessment. |
| `confidence` | How strongly the detector considers its evidence to support the verdict. |
| `severity` | The assessed potential impact, separately from confidence. |

The descriptions below document the current rules, including limitations relevant to validation. A confirmed missing setting, a version match, and demonstrated code execution are different kinds of evidence. Severity and confidence should be reviewed with that distinction in mind.

OWASP ZAP provides optional secondary validation; it is not the engine behind every category. SQL and command injection have optional active ZAP cross-checks, while [zap_validation.py](backend/app/scanners/zap_validation.py) supports passive corroboration for selected detectors. Service fingerprinting uses Nmap and TLS analysis uses SSLyze.

### 1. SQL Injection

**Weakness and impact:** Untrusted input changes the meaning of a database query. Depending on the application's database permissions and query, this can expose records or bypass intended query conditions.

**Detection technique:** The detector discovers or uses configured input parameters and compares controlled probes with a benign baseline:

- **Error-based:** A quote probe produces a recognised database error signature that was absent from the baseline.
- **Boolean-based:** An always-true condition resembles the normal response while an always-false condition changes it.
- **Time-based:** A database delay probe exceeds the configured response-time difference threshold.

**Classification:** Any of these signals can produce `CONFIRMED`. An error signature, or combined boolean and timing evidence, receives high confidence. A boolean-only or timing-only result receives medium confidence. Evidence records the tested parameter, payloads, response information, and timings.

**Evidence limits:** Response differences and isolated delays can have causes other than SQL execution. Repeated controls and independent corroboration strengthen the result; the probes do not demonstrate every possible database impact.

**Implementation:** [sql_injection.py](backend/app/scanners/sql_injection.py).

### 2. Command Injection

**Weakness and impact:** User-controlled input reaches an operating-system command in a way that changes what the shell executes. The potential impact depends on the privileges of the application process.

**Detection technique:** The detector compares a normal input with a harmless command intended to print a random marker and a short delay command. It records whether the marker appears in the response and how much longer the delay request takes than the baseline.

**Classification:** Marker presence produces `CONFIRMED` with high confidence. A delay exceeding the threshold produces `CONFIRMED` with medium confidence. Both signals together receive high confidence.

**Evidence limits:** The current implementation checks marker presence in the response, so an application that simply echoes the submitted input could trigger a false positive. Marker reflection alone is not definitive proof of command execution. A single timing difference also requires review for network or server variability.

**Implementation:** [command_injection.py](backend/app/scanners/command_injection.py).

### 3. Cross-Site Scripting (XSS)

**Weakness and impact:** Untrusted input executes as JavaScript in a browser under the application's origin, potentially affecting the user's interaction with the application.

**Detection technique:** The detector submits a unique JavaScript canary to discovered or configured inputs and uses Chromium to observe its execution. The canary's controlled effect is to set a specific DOM attribute to the generated marker.

**Classification:** `CONFIRMED`, high confidence, requires observing the expected DOM change. Reflection in an HTTP response without observed browser execution is classified as `NOT_DETECTED` by this module.

**Evidence limits:** The result covers the tested input and browser interaction. An untested rendering context or execution path may behave differently.

**Implementation:** [xss.py](backend/app/scanners/xss.py).

### 4. Unrestricted File Upload

**Weakness and impact:** An upload endpoint accepts inappropriate file types or exposes uploaded files in an unsafe location. Actual impact depends on storage, access controls, and whether the server executes uploaded content.

**Detection technique:** The detector submits plain-text canaries as an ordinary `.txt` control, with a script-capable `.php` extension, and with mismatched MIME metadata. The files contain no executable PHP. It then attempts to retrieve the exact marker from a public URL.

**Classification:** A publicly retrievable script-extension canary produces `CONFIRMED`, high confidence, and critical severity under the current policy. An apparently accepted script-extension or MIME-mismatch upload without verified public retrieval produces `SUSPECTED`, medium confidence, and high severity.

**Evidence limits:** Acceptance and retrieval demonstrate an upload-policy concern, not server-side code execution. The critical severity assignment should be reviewed against the target's actual execution and storage behaviour.

**Implementation:** [file_upload.py](backend/app/scanners/file_upload.py).

### 5. Path Traversal / File Inclusion

**Weakness and impact:** A file-selection parameter permits access outside the application's intended content directory, potentially exposing files available to the application process.

**Detection technique:** The detector submits relative traversal and absolute-path variants targeting a controlled canary file. The DVWA lab mounts this file outside its web root; other targets must supply the canary path and expected marker through configuration.

**Classification:** `CONFIRMED`, high confidence, requires the exact canary marker in a test response, absent from the permitted baseline response. No successful canary retrieval produces `NOT_DETECTED`.

**Evidence limits:** This demonstrates access to the tested file outside the intended directory. It does not demonstrate arbitrary file access or execution of an included file.

**Implementation:** [path_traversal.py](backend/app/scanners/path_traversal.py).

### 6. Cross-Site Request Forgery (CSRF)

**Weakness and impact:** A state-changing operation can be induced through a cross-site browser request using the victim's existing session, without valid verification of the user's intent.

**Detection technique:** The detector inspects forms for anti-CSRF tokens and compares token values across independent sessions. When an action is explicitly configured for active testing, it submits the request without the token and with an unrelated Origin/Referer. Success is assessed using a configured response indicator or response status. A configured reset value allows the test action to be reversed.

**Classification:** An active request judged successful produces `CONFIRMED`, high confidence; rejection produces `NOT_DETECTED`. Without an active result, missing tokens or identical token values across sessions also produce `CONFIRMED`, but with medium confidence under the current rules.

**Evidence limits:** Token absence or equality alone does not establish browser-exploitable CSRF: origin checks, cookie behaviour, and other protections may matter. Response success should be checked against an actual state change. These passive and response-based verdicts need stronger validation before claiming a demonstrated cross-site attack.

**Implementation:** [csrf.py](backend/app/scanners/csrf.py).

### 7. Broken Access Control / IDOR

**Weakness and impact:** Changing an object identifier exposes another user's protected object because the application fails to enforce object-level authorisation.

**Detection technique:** Two synthetic lab accounts establish legitimate responses for their own objects. User A then requests User B's object using A's session. Owner fields or response hashes attribute the returned data to an account. An unauthenticated request provides an additional exposure control.

**Classification:** Data attributable to B returned to A produces `CONFIRMED`, high confidence. A successful but unattributable response produces `SUSPECTED`. Indistinguishable objects produce `INCONCLUSIVE`. Refused access or a response containing A's own object produces `NOT_DETECTED`.

**Evidence limits:** The tested object must be intended to be private. Publicly accessible data is not automatically an authorisation flaw. HTTP success alone does not establish ownership or unauthorised disclosure.

**Implementation:** [idor.py](backend/app/scanners/idor.py).

### 8. Authentication / Session / JWT Weaknesses

**Weakness and impact:** The server trusts a session token without adequate integrity verification, potentially accepting a modified identity. This module also inspects token expiration information.

**Detection technique:** A lab account obtains a genuine JWT. Valid-token, absent-token, and structurally invalid-token controls establish whether the session-check endpoint distinguishes authentication reliably. The detector then submits unsigned and signature-invalidated tokens containing a modified identity claim.

**Classification:** Acceptance of a forged token as an authenticated session produces `CONFIRMED`. Returning the modified identity gives high confidence and critical severity; acceptance without that identity evidence gives medium confidence and high severity. Issued unsigned tokens also produce `CONFIRMED`. A missing `exp` claim produces `SUSPECTED`. Unreliable authentication controls produce `INCONCLUSIVE`.

**Evidence limits:** A missing expiration claim does not prove unlimited session lifetime because the server may enforce expiry separately. The module tests these JWT behaviours rather than every form of session-management weakness.

**Implementation:** [jwt_session.py](backend/app/scanners/jwt_session.py).

### 9. Weak Authentication Controls

**Weakness and impact:** Login behaviour reveals account existence or fails to show protection against repeated failed authentication attempts, making account discovery or password guessing easier.

**Detection technique:** A bounded series of failed logins checks for HTTP throttling, lockout, or CAPTCHA indicators. When a known username is configured, the detector compares its failed-login response with a randomly generated nonexistent username, or queries a configured account-lookup endpoint for a response difference.

**Classification:** An account-enumeration signal produces `CONFIRMED`, high confidence. No observed throttling within the attempt budget produces `CONFIRMED`, medium confidence. Observed throttling without an enumeration signal produces `NOT_DETECTED`; enumeration is skipped if no known username is available.

**Evidence limits:** The result establishes that protection was not observed within the configured attempt budget, not that no protection exists at a higher threshold or over a longer window. This test does not recover passwords.

**Implementation:** [weak_auth.py](backend/app/scanners/weak_auth.py).

### 10. Server-Side Request Forgery (SSRF)

**Weakness and impact:** User-controlled input causes a server to request a destination outside its intended access policy, potentially exposing resources reachable from the server's network.

**Detection technique:** The detector starts a controlled callback listener and submits its URL with a unique, unguessable path to a URL-fetching feature. The Juice Shop preset uses its profile-image URL importer and restores the previous image setting afterward.

**Classification:** A callback at the unique path supplied to the target produces `CONFIRMED`, high confidence. No matching callback produces `NOT_DETECTED`.

**Evidence limits:** The callback demonstrates a server-side fetch to the controlled destination. Whether that fetch violates policy must be assessed for the feature; legitimate URL importers also fetch URLs. The test does not demonstrate unrestricted access to other internal services or cloud metadata.

**Implementation:** [ssrf.py](backend/app/scanners/ssrf.py).

### 11. XML External Entity (XXE)

**Weakness and impact:** An XML parser resolves externally referenced resources from untrusted XML, potentially causing unintended network requests or local-file disclosure.

**Detection technique:** The detector submits XML declaring an external entity that references a controlled callback URL. A second probe references a harmless local file, defaulting to `/etc/os-release`, and checks for a distinctive content marker. An XML endpoint must be configured or supplied by a lab preset.

**Classification:** A callback or reflected external-resource content produces `CONFIRMED`, high confidence. Neither signal produces `NOT_DETECTED`.

**Evidence limits:** The result establishes the observed external-entity behaviour for the tested parser and endpoint. It does not establish access to every file or network destination.

**Implementation:** [xxe.py](backend/app/scanners/xxe.py).

### 12. Sensitive-File Exposure

**Weakness and impact:** Files intended to remain private are served through web requests, potentially revealing configuration, credentials, source information, backups, or logs.

**Detection technique:** The detector requests candidate paths and compares their HTTP status and response length against a random nonexistent path. This comparison aims to avoid treating a single-page application's catch-all response as an exposed file. Evidence retains response metadata rather than file bodies.

**Classification:** A response below HTTP 400 that differs from the baseline status/length is treated as exposure and produces `CONFIRMED`, high confidence. Severity follows the candidate category: credential stores are critical, configuration/repository metadata high, backups/logs/confidential documents medium, and source maps/hidden internal files low.

**Evidence limits:** Status and length differences do not verify file contents. Dynamic error pages or redirects can create false positives, while different files of equal response length can be missed. Positive findings require content and access-policy review before concluding that sensitive data was disclosed.

**Implementation:** [sensitive_files.py](backend/app/scanners/sensitive_files.py).

### 13. Known Vulnerable Services

**Weakness and impact:** An exposed network service matches a product/version associated with known vulnerabilities, or uses a protocol identified by the detector as insecure.

**Detection technique:** Nmap fingerprints services and versions. The module correlates service information with NVD records and curated fallback signatures, then uses SearchSploit metadata to check for public exploit availability. It does not execute those exploits.

**Classification:** The aggregate result is based on the highest-ranked match. A `known_cve` match produces `CONFIRMED`, high confidence; other match categories produce `SUSPECTED`, medium confidence. Public exploit availability can raise the reported severity to critical under the current policy.

**Evidence limits:** A service fingerprint and CVE match establish a potentially affected installation, not demonstrated exploitation. Inaccurate banners, backported fixes, configuration requirements, and incomplete vulnerability matching can affect applicability. Public exploit availability is a risk indicator rather than evidence that the exploit works on this target.

**Implementation:** [vulnerable_services.py](backend/app/scanners/vulnerable_services.py).

### 14. Security Misconfiguration

**Weakness and impact:** Deployment settings omit defensive controls or expose operational information and management features unnecessarily.

**Detection technique:** GET requests inspect security headers, session-cookie attributes, directory listings, default server pages, verbose errors, and diagnostic endpoints. The detector also records technology/version disclosure. Endpoint checks use content signatures and a missing-page baseline to reduce catch-all false positives.

**Classification:** Any recognised weakness produces `CONFIRMED`, high confidence. The most severe observed weakness determines the aggregate severity. Missing headers and default pages generally receive lower severity than exposed diagnostic information.

**Evidence limits:** A confirmed missing header or exposed default page is a configuration observation, not proof of account compromise or code execution. Interpretation depends on whether the control or endpoint is appropriate for the application.

**Implementation:** [misconfiguration.py](backend/app/scanners/misconfiguration.py).

### 15. Weak TLS Configuration

**Weakness and impact:** A TLS service accepts weak cryptographic options, presents problematic certificate properties, or exhibits a recognised TLS vulnerability, potentially weakening transport confidentiality or server authentication.

**Detection technique:** SSLyze enumerates accepted protocols and cipher suites, analyses certificates, and performs specialised probes for named TLS vulnerabilities. The detector evaluates old protocol versions, weak cipher markers, certificate trust and expiry, signature/key strength, and results for vulnerabilities such as Heartbleed, ROBOT, CCS injection, and insecure renegotiation.

**Classification:** The highest-severity observation determines the aggregate result. A protocol, cipher, or named-vulnerability finding produces `CONFIRMED`, high confidence. A certificate finding produces `SUSPECTED`, medium confidence. No recognised issue produces `NOT_DETECTED`.

**Evidence limits:** The verdict applies to the scanned TLS endpoint and the checks completed. Certificate trust depends on the scanner's trust context, which may differ from a private lab's configured clients. The aggregate status reflects the worst finding's category even when several kinds of issue coexist.

**Implementation:** [weak_tls.py](backend/app/scanners/weak_tls.py).

## Implementation stack

| Layer            | Technology                                                                   |
| ---------------- | ---------------------------------------------------------------------------- |
| Backend          | FastAPI, SQLAlchemy (async), Alembic, [uv](https://docs.astral.sh/uv/)       |
| Storage          | PostgreSQL, bind-mounted to the host so data survives container restarts     |
| Frontend         | React 19, TypeScript, Vite, Tailwind CSS v4, react-router                    |
| Detection engine | Python, one module per vulnerability category under `backend/app/scanners/`  |
| Deployment       | Docker Compose (root stack + separate `lab/` compose for vulnerable targets) |
| CI/CD            | GitHub Actions — backend lint/test, frontend lint/build, Docker image builds |

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

### Screenshots

**Sign in** — operator access with temporary lockout after repeated failed attempts.

![VulnVista sign-in page](docs/screenshots/vulnvista-login.png)

**Registered targets** — authorization-scoped target records with risk load, scan count, and last activity.

![Registered targets page](docs/screenshots/vulnvista-target.png)

**Finding detail** — a confirmed OS command injection with CVSS, CWE, OWASP mapping, remediation guidance, and probe timing evidence.

![OS command injection finding detail](docs/screenshots/vulnvista-detection.png)

**Evidence workspace** — stored detector evidence per finding, with observation history and workflow state.

![Evidence workspace page](docs/screenshots/vulnvista-evidence.png)

## Quality and safety checklist

- Detectors run only against the approved target allowlist — no arbitrary public hosts.
- Only synthetic accounts, files, and data are used or seeded.
- No destructive payloads, no denial-of-service, no automatic exploitation for system control.
- A detector failure never aborts the rest of a scan.
- Every finding retains a detector ID, scan ID, and evidence for reproducibility.
- The environment runs reproducibly with Docker Compose; secrets stay out of Git.

Full checklist: [implementation plan §18](VulnVista_IMPLEMENTATION_PLAN.md#18-security-and-ethical-controls-checklist).

## Standards and methodology

| Area                         | Standard     | Project use                                                |
| ---------------------------- | ------------ | ---------------------------------------------------------- |
| Vulnerability classes        | OWASP Top 10 | Structures the detector catalogue and dashboard categories |
| Weakness classification      | CWE          | Attached to each finding where applicable                  |
| Known-vulnerability tracking | CVE          | Attached to vulnerable-service findings                    |
| Technical severity           | CVSS v3.1    | Consistent severity baseline where a score applies         |

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
