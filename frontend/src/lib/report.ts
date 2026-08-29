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

/** Path scope of a scoped run — attached to the report so the excluded surface
 * is visible alongside the findings. */
export interface ReportScope {
  inScope: string[];
  outOfScope: string[];
}

function scopeSection(scope: ReportScope): string[] {
  const rows = ["Scope,Path"];
  for (const path of scope.inScope) rows.push(`${csvCell("in_scope")},${csvCell(path)}`);
  for (const path of scope.outOfScope) rows.push(`${csvCell("out_of_scope")},${csvCell(path)}`);
  return [...rows, ""]; // trailing blank line separates the scope block from findings
}

export function downloadFindingsReport(findings: Finding[], scope?: ReportScope) {
  const rows = [
    ...(scope ? scopeSection(scope) : []),
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
