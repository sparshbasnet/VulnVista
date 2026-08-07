# VulnVista Implementation Plan

## 1. Purpose

This implementation plan converts the approved VulnVista proposal into an eight-week development roadmap from project setup through final delivery.

VulnVista will be implemented as a controlled vulnerability-assessment platform that detects, validates, stores, prioritises, and presents findings from intentionally vulnerable laboratory systems. The implementation will cover fifteen vulnerability categories and integrate them into a common FastAPI backend, PostgreSQL database, React dashboard, containerised deployment, CI/CD workflow, reporting module, and evaluation process.

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
15. Final technical documentation, academic report, presentation, and demonstration.

---

# 3. High-Level System Workflow

```text
Authorised User
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
│   │   ├── core/
│   │   ├── database/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   ├── scanners/
│   │   │   ├── base.py
│   │   │   ├── sql_injection.py
│   │   │   ├── command_injection.py
│   │   │   ├── xss.py
│   │   │   ├── file_upload.py
│   │   │   ├── idor.py
│   │   │   ├── jwt_session.py
│   │   │   ├── path_traversal.py
│   │   │   ├── csrf.py
│   │   │   ├── vulnerable_services.py
│   │   │   ├── misconfiguration.py
│   │   │   ├── ssrf.py
│   │   │   ├── xxe.py
│   │   │   ├── sensitive_files.py
│   │   │   ├── weak_auth.py
│   │   │   └── weak_tls.py
│   │   └── main.py
│   ├── tests/
│   ├── pyproject.toml
│   └── Dockerfile
│
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   ├── components/
│   │   ├── services/
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
└── IMPLEMENTATION_PLAN.md
```

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

---

# 8. Eight-Week Implementation Roadmap

# Week 1 — Project Foundation, Architecture and Laboratory

## Objectives

Build the technical foundation required by every later milestone.

## Tasks

### Project Management

- [ ] Confirm final scope.
- [ ] Confirm the fifteen vulnerability categories.
- [ ] Confirm team responsibilities.
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
- [ ] Configure PostgreSQL.
- [ ] Add SQLAlchemy.
- [ ] Configure migrations.
- [ ] Add environment configuration.
- [ ] Add `.env.example`.
- [ ] Add logging framework.

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

## Week 1 Milestone — M1: Scope, Architecture and Lab Foundation

### Acceptance Criteria

- Repository is operational.
- Backend and frontend start locally.
- PostgreSQL connection works.
- Initial laboratory targets are reachable.
- Shared detector interface is documented.
- Database design is approved.
- Safety boundary is documented.

---

# Week 2 — Core Framework + Vulnerabilities 1–3

## Platform Tasks

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

## Vulnerability Milestone V1 — SQL Injection

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

## Vulnerability Milestone V2 — Command Injection

**Target:** DVWA  
**Risk:** Critical

### Implementation Tasks

- [ ] Identify command injection endpoint.
- [ ] Establish baseline response.
- [ ] Send harmless unique marker or controlled timing canary.
- [ ] Confirm behavioural difference.
- [ ] Prevent destructive operating-system commands.
- [ ] Capture evidence.
- [ ] Add severity/confidence.
- [ ] Add CWE mapping.
- [ ] Add remediation guidance.
- [ ] Implement tests.
- [ ] Integrate with shared schema.

### Acceptance Criteria

The detector confirms command execution only through a harmless marker/timing condition and stores evidence in the shared finding structure.

---

## Vulnerability Milestone V3 — Cross-Site Scripting (XSS)

**Target:** DVWA / OWASP Juice Shop  
**Risk:** Medium–High

### Implementation Tasks

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

## Week 2 Milestone — M2: Core Framework + First Three Detectors

### Acceptance Criteria

- Core scan orchestration works.
- Findings persist to PostgreSQL.
- SQL injection works.
- Command injection works.
- XSS works.
- A scan can execute multiple detectors without one detector failure terminating the scan.

---

# Week 3 — Vulnerabilities 4–7 + Backend Integration

## Vulnerability Milestone V4 — Unrestricted File Upload

**Target:** DVWA  
**Risk:** Critical

### Tasks

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

## Vulnerability Milestone V5 — Path Traversal / File Inclusion

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

## Vulnerability Milestone V6 — Cross-Site Request Forgery (CSRF)

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

## Vulnerability Milestone V7 — Broken Access Control / IDOR

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

## Backend Tasks

- [ ] Create finding endpoints.
- [ ] Create evidence endpoints.
- [ ] Add scan-result retrieval.
- [ ] Add pagination.
- [ ] Add filtering by target.
- [ ] Add filtering by vulnerability.
- [ ] Add filtering by severity.
- [ ] Add validation-status filtering.

## Week 3 Milestone — M3A: Seven Integrated Vulnerabilities

### Acceptance Criteria

Seven detectors produce structured findings and their results are queryable using the backend API.

---

# Week 4 — Vulnerabilities 8–11 + Dashboard

## Vulnerability Milestone V8 — Authentication / Session / JWT Weaknesses

**Target:** OWASP Juice Shop  
**Risk:** High–Critical

### Tasks

- [ ] Obtain controlled laboratory JWT/session.
- [ ] Parse JWT header and claims.
- [ ] Check expiration claims.
- [ ] Check important token properties.
- [ ] Submit malformed token.
- [ ] Submit expired test token where supported.
- [ ] Test controlled token modification.
- [ ] Verify invalid signatures are rejected.
- [ ] Check session handling relevant to the target.
- [ ] Never use real credentials/tokens.
- [ ] Capture claims and responses safely.
- [ ] Mask sensitive values in logs.
- [ ] Add severity/confidence.
- [ ] Add CWE/remediation.
- [ ] Integrate detector.

### Acceptance Criteria

The detector reports a finding only when controlled invalid authentication/session/token conditions are accepted or an explicitly defined weakness is demonstrated.

---

## Vulnerability Milestone V9 — Weak Authentication Controls

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

## Vulnerability Milestone V10 — Server-Side Request Forgery (SSRF)

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

## Vulnerability Milestone V11 — XML External Entity (XXE)

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

## Dashboard MVP Tasks

- [ ] Dashboard layout.
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

## Week 4 Milestone — M3: Majority of Vulnerabilities Integrated

### Acceptance Criteria

- At least 11 vulnerability modules work end-to-end.
- Results pass through detector → API → database → dashboard.
- Dashboard MVP can display real detector findings.

---

# Week 5 — Vulnerabilities 12–15 + Complete MVP

## Vulnerability Milestone V12 — Sensitive-File Exposure

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

## Vulnerability Milestone V13 — Known Vulnerable Services

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

## Vulnerability Milestone V14 — Security Misconfiguration

**Target:** All laboratory targets  
**Risk:** Medium–High

### Tasks

- [ ] Check security headers.
- [ ] Check cookie security attributes.
- [ ] Check exposed directory listing.
- [ ] Check default pages.
- [ ] Check debug/error-information leakage.
- [ ] Check obviously unsafe exposed services.
- [ ] Define each check separately.
- [ ] Avoid reporting purely informational items as high severity.
- [ ] Store individual evidence.
- [ ] Add confidence/remediation.
- [ ] Integrate detector.

### Acceptance Criteria

The detector reports clearly defined configuration weaknesses with sufficient evidence and appropriate severity.

---

## Vulnerability Milestone V15 — Weak TLS Configuration

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

# Week 5 — Platform Completion Tasks

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

## Week 5 Milestone — M4: MVP Complete / All 15 Vulnerabilities

### Acceptance Criteria

- All fifteen vulnerability detectors are implemented.
- All detectors use the common framework.
- Findings are persisted.
- Dashboard displays the findings.
- Core end-to-end workflow works.

### Feature Freeze

After this milestone, avoid adding major new features. Weeks 6–8 should focus on integration, validation, documentation, performance, defects, and delivery.

---

# Week 6 — Full Integration, Reporting, Containers and CI/CD

## Backend Integration

- [ ] Finalise scan orchestration.
- [ ] Finalise detector registry.
- [ ] Add per-detector timeout.
- [ ] Add scan cancellation where appropriate.
- [ ] Add partial scan handling.
- [ ] Finalise error capture.
- [ ] Add audit records.
- [ ] Add database indexes.
- [ ] Validate migrations.
- [ ] Add API documentation.

## Scan History

- [ ] List previous scans.
- [ ] Open previous scan.
- [ ] Compare repeated scans.
- [ ] Identify new findings.
- [ ] Identify recurring findings.
- [ ] Identify remediated findings.
- [ ] Preserve historical findings.

## Reporting

- [ ] Create report template.
- [ ] Add target summary.
- [ ] Add scan information.
- [ ] Add severity summary.
- [ ] Add detailed findings.
- [ ] Add evidence summary.
- [ ] Add CWE/CVE/CVSS references.
- [ ] Add remediation.
- [ ] Export HTML.
- [ ] Export PDF if practical within schedule.

## Dockerisation

- [ ] Backend Dockerfile.
- [ ] Frontend Dockerfile.
- [ ] PostgreSQL service.
- [ ] Docker Compose.
- [ ] Environment variables.
- [ ] Persistent database volume.
- [ ] Health checks.
- [ ] Internal/private laboratory networking.
- [ ] Reproducible setup documentation.

## CI/CD

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
Unit Tests
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
- [ ] API tests.
- [ ] Docker build.
- [ ] Prevent secrets from being committed.
- [ ] Create release candidate workflow.

## Week 6 Milestone — M5A: End-to-End Integrated Prototype

### Acceptance Criteria

A new environment can start the platform through documented container instructions and execute an end-to-end scan through the dashboard/backend.

---

# Week 7 — Detector Validation, Accuracy and Performance

This week is primarily evaluation rather than new feature development.

# 9. Detector Validation Matrix

Create a matrix similar to:

| # | Detector | Vulnerable Test | Secure/Negative Test | Repeat Test | Evidence Review | Result |
|---|---|---|---|---|---|---|
| 1 | SQL Injection | ☐ | ☐ | ☐ | ☐ | Pending |
| 2 | Command Injection | ☐ | ☐ | ☐ | ☐ | Pending |
| 3 | XSS | ☐ | ☐ | ☐ | ☐ | Pending |
| 4 | File Upload | ☐ | ☐ | ☐ | ☐ | Pending |
| 5 | Path Traversal | ☐ | ☐ | ☐ | ☐ | Pending |
| 6 | CSRF | ☐ | ☐ | ☐ | ☐ | Pending |
| 7 | IDOR | ☐ | ☐ | ☐ | ☐ | Pending |
| 8 | JWT/Session | ☐ | ☐ | ☐ | ☐ | Pending |
| 9 | Weak Authentication | ☐ | ☐ | ☐ | ☐ | Pending |
| 10 | SSRF | ☐ | ☐ | ☐ | ☐ | Pending |
| 11 | XXE | ☐ | ☐ | ☐ | ☐ | Pending |
| 12 | Sensitive Files | ☐ | ☐ | ☐ | ☐ | Pending |
| 13 | Vulnerable Services | ☐ | ☐ | ☐ | ☐ | Pending |
| 14 | Misconfiguration | ☐ | ☐ | ☐ | ☐ | Pending |
| 15 | Weak TLS | ☐ | ☐ | ☐ | ☐ | Pending |

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

- [ ] Test all 15 detectors.
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

- All 15 detector implementations have validation results.
- Critical defects are resolved.
- Evaluation metrics are available.
- CI/CD passes.
- Container deployment works.
- Dashboard works with real findings.
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
- [ ] Verify demo accounts.
- [ ] Verify demo target state.

## Technical Documentation

- [ ] README.
- [ ] Installation guide.
- [ ] Configuration guide.
- [ ] Architecture documentation.
- [ ] Database documentation.
- [ ] API documentation.
- [ ] Detector documentation.
- [ ] Testing guide.
- [ ] Safety/ethical controls.
- [ ] Troubleshooting guide.

## Academic Report

Suggested evidence to include:

- architecture
- database design
- detector framework
- explanation of each detector
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
1. Open VulnVista dashboard
2. Show approved targets
3. Start a selected scan
4. Show scan progress/status
5. Show several detected vulnerabilities
6. Open one finding
7. Explain evidence and confidence
8. Show CWE/CVE/CVSS data where applicable
9. Change remediation status
10. Show scan history/comparison
11. Export report
12. Briefly show CI/CD and Docker deployment
```

It is not necessary to run all fifteen detectors live during a short presentation. All fifteen should be demonstrable and have recorded validation results.

## Presentation

- [ ] Problem.
- [ ] Proposed solution.
- [ ] Architecture.
- [ ] Detection engine.
- [ ] 15 vulnerabilities.
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

- working VulnVista prototype
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

| Milestone | Target | Expected Outcome |
|---|---|---|
| M1 | End Week 1 | Scope, architecture and laboratory foundation |
| V1 | Week 2 | SQL injection detector |
| V2 | Week 2 | Command injection detector |
| V3 | Week 2 | XSS detector |
| M2 | End Week 2 | Core framework + first 3 detectors |
| V4 | Week 3 | Unrestricted file-upload detector |
| V5 | Week 3 | Path traversal/file inclusion detector |
| V6 | Week 3 | CSRF detector |
| V7 | Week 3 | IDOR/broken access-control detector |
| M3A | End Week 3 | Seven integrated detectors |
| V8 | Week 4 | Authentication/session/JWT detector |
| V9 | Week 4 | Weak-authentication detector |
| V10 | Week 4 | SSRF detector |
| V11 | Week 4 | XXE detector |
| M3 | End Week 4 | Eleven integrated detectors + dashboard MVP |
| V12 | Week 5 | Sensitive-file exposure detector |
| V13 | Week 5 | Known vulnerable-service detector |
| V14 | Week 5 | Security-misconfiguration detector |
| V15 | Week 5 | Weak-TLS detector |
| M4 | End Week 5 | All 15 detectors + platform MVP |
| M5A | End Week 6 | Complete integrated/containerised system |
| M5 | End Week 7 | Validated release candidate |
| M6 | End Week 8 | Final prototype, report and presentation |

---

# 13. Milestone Dependency Flow

```text
M1 Foundation
 |
 +--> Detector Interface
 |       |
 |       +--> V1 SQL Injection
 |       +--> V2 Command Injection
 |       +--> V3 XSS
 |       +--> V4 File Upload
 |       +--> V5 Path Traversal
 |       +--> V6 CSRF
 |       +--> V7 IDOR
 |       +--> V8 JWT/Session
 |       +--> V9 Weak Authentication
 |       +--> V10 SSRF
 |       +--> V11 XXE
 |       +--> V12 Sensitive Files
 |       +--> V13 Vulnerable Services
 |       +--> V14 Misconfiguration
 |       +--> V15 Weak TLS
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

# 14. Suggested Parallel Team Workstreams

The proposal identifies three main responsibility areas. Development should still use shared ownership where required.

## Workstream A — Cybersecurity / Detector Development

Primary focus:

- laboratory target configuration
- detector design
- safe payloads/tests
- evidence collection
- validation rules
- security classifications
- detector testing

## Workstream B — Backend / Cloud / CI/CD

Primary focus:

- FastAPI
- SQLAlchemy
- PostgreSQL
- scanner orchestration
- API
- Docker
- automated tests
- CI/CD
- deployment

## Workstream C — Frontend / Data Visualisation

Primary focus:

- React/TypeScript
- dashboard
- scan status
- findings table
- charts
- finding detail
- evidence presentation
- scan history
- remediation workflow
- reporting presentation

## Shared Responsibilities

All team members should participate in:

- architecture decisions
- integration
- validation
- documentation
- report writing
- presentation
- live demonstration

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

The final endpoint design can be adapted during development.

---

# 16. Dashboard Implementation Checklist

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

## Detector Tests

Each detector should have:

- positive fixture/test
- negative fixture/test where practical
- timeout behaviour
- target/network-error handling

## API Tests

Test:

- target creation
- target rejection
- scan creation
- findings retrieval
- filtering
- finding-status updates
- report generation

## Integration Tests

Test:

```text
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
- [ ] Scan audit logging.
- [ ] Secrets excluded from Git.
- [ ] Final demo stays inside contained environment.

---

# 19. Risk-Control Gates

## End of Week 2

If the shared detector framework is unstable:

**Stop adding new detector complexity and fix the common interface first.**

## End of Week 3

If seven detectors are not integrated:

**Simplify evidence/UI features temporarily and prioritise detector completion.**

## End of Week 4

If fewer than eleven detectors work:

**Allocate additional team capacity to detector implementation.**

## End of Week 5

**Feature freeze.**

All fifteen detectors should exist. No unnecessary major features should be introduced after this point.

## Week 6

Integration and deployment.

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
- [ ] Target allowlisting works.
- [ ] Scan management works.
- [ ] SQL injection detector works.
- [ ] Command injection detector works.
- [ ] XSS detector works.
- [ ] Unrestricted file-upload detector works.
- [ ] IDOR detector works.
- [ ] Authentication/session/JWT detector works.
- [ ] Path traversal detector works.
- [ ] CSRF detector works.
- [ ] Known vulnerable-services detector works.
- [ ] Security-misconfiguration detector works.
- [ ] SSRF detector works.
- [ ] XXE detector works.
- [ ] Sensitive-file exposure detector works.
- [ ] Weak-authentication detector works.
- [ ] Weak-TLS detector works.
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
2. Shared detector interface
3. Database schema
4. SQL injection
5. Command injection
6. XSS
7. File upload
8. IDOR
9. Path traversal
10. CSRF
11. JWT/session
12. Weak authentication
13. SSRF
14. XXE
15. Sensitive files
16. Vulnerable services
17. Misconfiguration
18. Weak TLS
19. Backend integration
20. Dashboard
21. History/remediation
22. Reporting
23. Docker/CI-CD
24. Validation
25. Documentation/demo
```

The core academic value should remain **repeatable detection + explicit validation + structured evidence**, rather than adding many secondary features that cannot be tested properly within eight weeks.

---

# 23. Weekly Completion Summary

## Week 1
**Foundation complete**

## Week 2
**3/15 vulnerabilities complete**

- SQL Injection
- Command Injection
- XSS

## Week 3
**7/15 vulnerabilities complete**

- + File Upload
- + Path Traversal
- + CSRF
- + IDOR

## Week 4
**11/15 vulnerabilities complete**

- + JWT/Session
- + Weak Authentication
- + SSRF
- + XXE

## Week 5
**15/15 vulnerabilities complete**

- + Sensitive Files
- + Known Vulnerable Services
- + Security Misconfiguration
- + Weak TLS

## Week 6
**End-to-end platform complete**

## Week 7
**Validated release candidate**

## Week 8
**Final submission and demonstration**

---

# 24. Final Delivery Target

At the end of Week 8, VulnVista should demonstrate the following complete lifecycle:

```text
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
