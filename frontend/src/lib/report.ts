import type { Finding } from "../types";

const COLUMNS: (keyof Finding)[] = [
  "vulnerability_name",
  "severity",
  "confidence",
  "validation_status",
  "finding_status",
  "cwe",
  "cve",
  "cvss_score",
  "owasp_category",
  "affected_endpoint",
  "evidence_summary",
  "detector_id",
  "created_at",
  "updated_at",
];

function csvCell(value: unknown): string {
  const text = value === null || value === undefined ? "" : String(value);
  return `"${text.replace(/"/g, '""')}"`;
}

export function downloadFindingsReport(findings: Finding[]) {
  const rows = [
    COLUMNS.join(","),
    ...findings.map((f) => COLUMNS.map((col) => csvCell(f[col])).join(",")),
  ];
  const blob = new Blob([rows.join("\n")], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `vulnvista-findings-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}
