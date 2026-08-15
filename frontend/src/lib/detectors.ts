// The 15 vulnerability categories from the implementation plan. `key` matches
// Finding.detector_id for the ones that are actually registered in the
// backend's DETECTOR_REGISTRY (backend/app/scanners/__init__.py) — the rest
// are still owned by teammates and not implemented yet, so the dashboard
// shows them honestly rather than inventing data for them.
export interface DetectorMeta {
  n: number;
  title: string;
  file: string;
  key: string | null;
}

export const DETECTORS: DetectorMeta[] = [
  { n: 1, title: "SQL Injection", file: "sql_injection.py", key: null },
  { n: 2, title: "Command Injection", file: "command_injection.py", key: "command_injection" },
  { n: 3, title: "Cross-Site Scripting", file: "xss.py", key: null },
  { n: 4, title: "File Upload", file: "file_upload.py", key: null },
  { n: 5, title: "Path Traversal", file: "path_traversal.py", key: null },
  { n: 6, title: "CSRF", file: "csrf.py", key: "csrf" },
  { n: 7, title: "Access Control / IDOR", file: "idor.py", key: null },
  { n: 8, title: "JWT / Session", file: "jwt_session.py", key: null },
  { n: 9, title: "Weak Authentication", file: "weak_auth.py", key: "weak_auth" },
  { n: 10, title: "SSRF", file: "ssrf.py", key: null },
  { n: 11, title: "XXE", file: "xxe.py", key: "xxe" },
  { n: 12, title: "Sensitive Files", file: "sensitive_files.py", key: "sensitive_files" },
  { n: 13, title: "Vulnerable Services", file: "vulnerable_services.py", key: "vulnerable_services" },
  { n: 14, title: "Misconfiguration", file: "misconfiguration.py", key: null },
  { n: 15, title: "Weak TLS", file: "weak_tls.py", key: "weak_tls" },
];
