# Sunil Sapkota — VulnVista user stories

Five published GitHub issues, one story per assigned vulnerability.

Owner: Sunil Sapkota (`sunil-9`). Target repository: `sparshbasnet/Advance-Project-NIT6150-`.
Project: [VulnVista](https://github.com/users/sparshbasnet/projects/1), using its existing **User Story** status column.
Issue state: Closed — Completed. All five issues are assigned to `sunil-9`.
Publication status: Created as issues #50–#54. Each issue includes the checked criteria, detection algorithm, implementation links, test verification, and related implementation task.

- [#50 Command Injection](https://github.com/sparshbasnet/Advance-Project-NIT6150-/issues/50)
- [#51 Weak Authentication Controls](https://github.com/sparshbasnet/Advance-Project-NIT6150-/issues/51)
- [#52 Sensitive-File Exposure](https://github.com/sparshbasnet/Advance-Project-NIT6150-/issues/52)
- [#53 Known Vulnerable Services](https://github.com/sparshbasnet/Advance-Project-NIT6150-/issues/53)
- [#54 Weak TLS Configuration](https://github.com/sparshbasnet/Advance-Project-NIT6150-/issues/54)

See [detection algorithm explanations](sunil-detection-algorithms.md) for the detailed logic and interpretation limits included in each issue.

Checked criteria below describe implemented detector work, not remediation of the intentionally vulnerable lab targets. Verification on 6 September 2026: all 82 tests in the five referenced test modules passed. Pytest reported a cache-write permission warning; no tests failed. Live lab scans were not rerun for these drafts.

---

## Issue 1: Command Injection — User Story — Sunil Sapkota

**Owner:** Sunil Sapkota (`sunil-9`)

### User story

As a security analyst, I want VulnVista to test discovered or configured input parameters for OS command injection so that I can identify potentially unsafe command execution and review the supporting evidence.

### Acceptance criteria — what we did

- [x] Implemented the command-injection detector with HTML form and URL query-parameter discovery.
- [x] Added configurable injection points and a DVWA lab preset.
- [x] Implemented runtime marker-output checks and blind timing checks against a benign baseline.
- [x] Classified observations into detection, validation status, severity, and confidence results.
- [x] Added optional OWASP ZAP corroboration and confidence-combination logic.
- [x] Added tests covering form parsing, evidence extraction, classification, profile registration, and ZAP result combination.

**Implementation:** `backend/app/scanners/command_injection.py`

**Tests:** `backend/tests/test_command_injection.py`

**Resolution:** Detector implementation and listed acceptance criteria completed.

---

## Issue 2: Weak Authentication Controls — User Story — Sunil Sapkota

**Owner:** Sunil Sapkota (`sunil-9`)

### User story

As a security analyst, I want VulnVista to check login responses for missing throttling and username enumeration so that I can identify authentication controls that need improvement.

### Acceptance criteria — what we did

- [x] Implemented login-form discovery with configurable paths and field names.
- [x] Supported form-encoded and JSON authentication requests, including a Juice Shop preset.
- [x] Implemented bounded failed-login attempts and detection of HTTP 429 or lockout/CAPTCHA response hints.
- [x] Compared known-account and synthetic-account responses for enumeration signals; skipped enumeration when no known username is configured.
- [x] Classified authentication observations into structured findings and handled missing login forms as scan errors.
- [x] Added tests covering classification, discovery, enumeration, preset selection, and missing-form errors.

**Implementation:** `backend/app/scanners/weak_auth.py`

**Tests:** `backend/tests/test_weak_auth.py`

**Resolution:** Detector implementation and listed acceptance criteria completed.

---

## Issue 3: Sensitive-File Exposure — User Story — Sunil Sapkota

**Owner:** Sunil Sapkota (`sunil-9`)

### User story

As a security analyst, I want VulnVista to identify publicly accessible sensitive-file candidates so that I can prioritise removal of exposed configuration, backup, and repository artifacts.

### Acceptance criteria — what we did

- [x] Implemented configurable candidate paths covering sensitive-file categories and Juice Shop lab files.
- [x] Probed a random nonexistent path to establish the target's baseline response.
- [x] Compared candidate status and content length with the baseline to filter matching SPA fallback responses.
- [x] Rejected HTTP error responses as file-exposure evidence.
- [x] Recorded file paths and response metadata without storing retrieved file bodies in finding evidence.
- [x] Added category-based severity/CWE mapping, remediation guidance, and tests for baseline filtering, classification, generic candidates, and lab presets.

**Implementation:** `backend/app/scanners/sensitive_files.py`

**Tests:** `backend/tests/test_sensitive_files.py`

**Resolution:** Detector implementation and listed acceptance criteria completed.

---

## Issue 4: Known Vulnerable Services — User Story — Sunil Sapkota

**Owner:** Sunil Sapkota (`sunil-9`)

### User story

As a security analyst, I want VulnVista to fingerprint network services and associate observed versions with vulnerability references so that I can prioritise patching using service and CVE evidence.

### Acceptance criteria — what we did

- [x] Integrated Nmap discovery and service/version fingerprinting with XML parsing for open ports and CPE identifiers.
- [x] Implemented application-CPE selection and CPE conversion for NVD vulnerability lookups.
- [x] Extracted CVE identifiers, severity, scores, and CWE information from NVD records.
- [x] Added curated fallback matching for selected lab services and insecure protocols.
- [x] Added optional SearchSploit metadata enrichment for public exploit availability without executing exploits.
- [x] Added tests for parsing, CVE metadata, fallback matching, unaffected-version controls, confidence classification, exploit-availability severity, and profile registration.

**Implementation:** `backend/app/scanners/vulnerable_services.py`

**Tests:** `backend/tests/test_vulnerable_services.py`

**Resolution:** Detector implementation and listed acceptance criteria completed.

---

## Issue 5: Weak TLS Configuration — User Story — Sunil Sapkota

**Owner:** Sunil Sapkota (`sunil-9`)

### User story

As a security analyst, I want VulnVista to assess TLS protocols, cipher suites, certificates, and supported implementation-vulnerability checks so that I can identify transport-security weaknesses and review remediation guidance.

### Acceptance criteria — what we did

- [x] Integrated SSLyze with configurable target ports and a scan timeout.
- [x] Classified deprecated SSL/TLS versions and weak cipher suites.
- [x] Assessed certificate trust, expiry, SHA-1 signatures, and key strength.
- [x] Processed Heartbleed, ROBOT, CCS injection, and secure-renegotiation observations.
- [x] Converted scanner observations into serializable evidence with severity, confidence, references, and remediation guidance.
- [x] Added tests for weak and strong configurations, certificate findings, named vulnerability classification, clean results, confidence, and profile registration.

**Implementation:** `backend/app/scanners/weak_tls.py`

**Tests:** `backend/tests/test_weak_tls.py`

**Resolution:** Detector implementation and listed acceptance criteria completed.
