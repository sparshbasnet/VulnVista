# How Sunil's five VulnVista detectors work

This describes the implementation at commit `b443dabe577828fc2bc3edabce5570bdd1ea8aab`. These are active checks against configured targets. Detection labels describe the code's decision rules; they are not proof that every reported issue is exploitable. The five test modules passed all 82 tests; live scans were not repeated for this documentation.

## Command Injection

**Algorithm: compare a benign request with output-marker and timing probes.**

1. Resolve the injection point from explicit scan configuration, a DVWA preset, or discovered HTML forms and URL query parameters.
2. Submit a benign value and measure its response time as the baseline.
3. Generate a random marker and submit a value containing a command separator followed by `echo <marker>`.
4. Search the response body for that marker and extract a short evidence snippet.
5. Submit a second value containing `sleep 5`. Calculate `delay = blind_response_ms - baseline_response_ms`.
6. If the marker appears, classify the result as `CONFIRMED` with high confidence. If only the delay is at least 4,000 ms, classify it as `CONFIRMED` with medium confidence. If neither signal appears, return `NOT_DETECTED`.
7. When configured, run a ZAP cross-check and combine its command-injection alerts with the manual result. Preserve payload, endpoint, parameter, and timing evidence.

**Interpretation limit:** The current marker check also matches an application simply reflecting the submitted input. One timing comparison can be affected by latency. The code's confirmation label should therefore be reviewed alongside the evidence.

**Code:** `backend/app/scanners/command_injection.py`, especially `classify()`, `_probe()`, and `combine_with_zap()`.

## Weak Authentication Controls

**Algorithm: bounded failed-login probing plus known/unknown-account response comparison.**

1. Resolve a login form or configured JSON endpoint, preserving required fixed/hidden fields. Juice Shop uses a preset.
2. Send up to 12 failed-login requests by default, using a configured known username or a synthetic account and random wrong passwords.
3. Stop when a response is HTTP 429 or contains a configured lockout/rate-limit/CAPTCHA keyword. If none appears within the attempt budget, report missing observed throttling.
4. If a known username is supplied, compare it with a randomly generated nonexistent username. Otherwise, skip enumeration.
5. For a configured enumeration endpoint, check whether the configured JSON field is truthy for the known account and absent/false for the unknown one. In Juice Shop this is the password-reset security-question lookup.
6. Otherwise, submit the same wrong password for both accounts. Different HTTP status codes or a response-text length difference greater than five characters trigger the enumeration heuristic.
7. Enumeration yields high confidence; absence of observed lockout alone yields medium confidence. Record response statuses, account-comparison signals, and the chosen method.

**Interpretation limit:** Twelve attempts cannot establish that throttling never occurs. Dynamic response content can produce an enumeration false positive. These checks do not guess a correct password.

**Code:** `backend/app/scanners/weak_auth.py`, especially `_check_rate_limit()`, `_check_enumeration_oracle()`, `_check_enumeration_login_diff()`, and `classify()`.

## Sensitive-File Exposure

**Algorithm: candidate-path probing with a nonexistent-path baseline.**

1. Load generic candidate paths for configuration, credentials, backups, repository metadata, logs, source maps, and other sensitive-file categories. Apply lab additions or a configured replacement list.
2. Request a random nonexistent path and record its HTTP status and actual response-body byte length.
3. Request each candidate path.
4. Reject responses with HTTP status 400 or greater. Reject candidates whose status and byte length both equal the baseline, which filters matching single-page-application fallback pages.
5. Treat remaining candidates as exposures and classify severity by file category. Select the highest-severity category for the combined result.
6. Store path, category, status, content type, and content length as evidence, together with checked paths and remediation guidance. Do not store the retrieved file bodies in finding evidence.

**Decision rule:** `exposed = status < 400 AND (status != baseline_status OR length != baseline_length)`.

**Interpretation limit:** This compares status and length, not file-content signatures. Dynamic fallback pages can cause false positives; a real file with matching status and length can be missed.

**Code:** `backend/app/scanners/sensitive_files.py`, especially `is_exposed()`, `_probe_baseline()`, `check()`, and `classify()`.

## Known Vulnerable Services

**Algorithm: service fingerprinting followed by vulnerability-reference matching.**

1. Run Nmap service/version detection against the configured ports or top-port selection and parse its XML output for open ports, products, versions, CPE identifiers, and script observations.
2. Match observations against curated signatures for selected vulnerable lab services and insecure protocols.
3. Select application CPE identifiers, convert supported CPE 2.2 identifiers to CPE 2.3, and query the NVD CVE API using `virtualMatchString`.
4. Extract CVE, CVSS severity, CWE, and description. Sort returned CVEs by score, retain the configured number per service, and deduplicate port/CVE pairs. NVD failures are treated as best-effort enrichment failures.
5. Optionally query SearchSploit for exploit-reference metadata for newly added NVD matches. The detector does not execute the returned exploits.
6. Rank matches by severity and exploit availability. The code labels a worst match in the `known_cve` category as `CONFIRMED`/high confidence; heuristic-only worst matches are `SUSPECTED`/medium confidence. Public exploit availability can raise severity to critical.
7. Return service/version evidence and vulnerability references, or `NOT_DETECTED` if no matches were found.

**Interpretation limit:** Fingerprints and CVE associations do not prove successful exploitation or account for every backported fix. The implementation does not independently evaluate all NVD applicability conditions. Missing fingerprints or failed lookups can reduce coverage. Nmap's default script expression is configurable (`default,safe`); this is active scanning, not passive observation.

**Code:** `backend/app/scanners/vulnerable_services.py`, especially `parse_nmap_xml()`, `match_heuristics()`, `_gather_matches()`, `_query_nvd()`, and `classify()`.

## Weak TLS Configuration

**Algorithm: SSLyze protocol observations followed by rule-based classification.**

1. Resolve the target host and port and run SSLyze under a configurable timeout.
2. Reduce completed scanner results into a serializable `TLSObservation` containing accepted protocols/ciphers, certificate properties, and implementation-vulnerability results.
3. Flag deprecated protocols: SSLv2/SSLv3 as critical, TLS 1.0 as high, and TLS 1.1 as medium.
4. Flag cipher names containing weak markers such as NULL, EXPORT, ANON, RC4, DES, or MD5.
5. Check certificate trust, expiry, SHA-1 signatures, RSA keys smaller than 2,048 bits, and EC keys smaller than 224 bits.
6. Process SSLyze findings for Heartbleed, ROBOT, CCS injection, and lack of secure renegotiation.
7. Combine all categories and choose the highest-severity finding. If that finding is a protocol, cipher, or implementation vulnerability, label the result `CONFIRMED`/high confidence; if it is a certificate finding, use `SUSPECTED`/medium confidence. Emit evidence and remediation guidance.

**Interpretation limit:** These are active TLS handshakes and vulnerability probes. Certificate trust depends on the scanner's trust configuration, and failed/incomplete individual checks are not evidence of a secure service. The highest-severity finding determines the combined confidence label.

**Code:** `backend/app/scanners/weak_tls.py`, especially `_observe()`, `classify_ciphers()`, `classify_certificate()`, `classify_vulnerabilities()`, and `classify()`.
