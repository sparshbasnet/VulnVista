export type ScanStatus = "QUEUED" | "RUNNING" | "COMPLETED" | "PARTIAL" | "FAILED" | "CANCELLED";

export type FindingStatus = "OPEN" | "IN_PROGRESS" | "REMEDIATED" | "ACCEPTED_RISK" | "FALSE_POSITIVE";

export type ValidationStatus = "NOT_DETECTED" | "SUSPECTED" | "CONFIRMED" | "INCONCLUSIVE" | "ERROR";

export interface Target {
  id: string;
  name: string;
  target_type: string;
  base_url: string | null;
  ip_address: string | null;
  environment: string;
  is_allowed: boolean;
  authorization_confirmed: boolean;
  created_at: string;
  updated_at: string;
}

export interface TargetCreatePayload {
  name: string;
  target_type: string;
  base_url: string;
  ip_address?: string | null;
  environment?: string;
  authorization_confirmed?: boolean;
  scan_config?: Record<string, unknown>;
}

export interface Scan {
  id: string;
  target_id: string;
  scan_profile: string;
  status: ScanStatus;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  initiated_by: string | null;
  error_summary: string | null;
  created_at: string;
}

export interface Evidence {
  id: string;
  finding_id: string;
  evidence_type: string;
  content: Record<string, unknown>;
  created_at: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  target_id: string;
  detector_id: string;
  vulnerability_name: string;
  severity: string;
  confidence: string;
  validation_status: ValidationStatus;
  description: string | null;
  affected_endpoint: string | null;
  parameter: string | null;
  evidence_summary: string | null;
  remediation: string | null;
  cwe: string | null;
  cve: string | null;
  cvss_score: number | null;
  owasp_category: string | null;
  finding_status: FindingStatus;
  created_at: string;
  updated_at: string;
  evidence: Evidence[];
}
