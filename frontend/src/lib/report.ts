import type { Finding } from "../types";

export type ReportFormat = "csv" | "doc";

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

// Human-readable column headers for the document report.
const COLUMN_LABELS: Record<string, string> = {
  vulnerability_name: "Vulnerability",
  severity: "Severity",
  confidence: "Confidence",
  validation_status: "Validation",
  finding_status: "Status",
  cwe: "CWE",
  cve: "CVE",
  cvss_score: "CVSS",
  owasp_category: "OWASP",
  affected_endpoint: "Endpoint",
  evidence_summary: "Evidence",
  detector_id: "Detector",
  created_at: "Created",
  updated_at: "Updated",
};

function csvCell(value: unknown): string {
  const text = value === null || value === undefined ? "" : String(value);
  return `"${text.replace(/"/g, '""')}"`;
}

function htmlEscape(value: unknown): string {
  const text = value === null || value === undefined ? "" : String(value);
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
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

function buildCsv(findings: Finding[], scope?: ReportScope): string {
  const rows = [
    ...(scope ? scopeSection(scope) : []),
    COLUMNS.join(","),
    ...findings.map((f) => COLUMNS.map((col) => csvCell(f[col])).join(",")),
  ];
  return rows.join("\n");
}

/** Build a Word-openable document (HTML with an .doc extension). Word and
 * Google Docs both render this as a formatted report with real tables. */
function buildDoc(findings: Finding[], scope?: ReportScope): string {
  const generated = new Date().toLocaleString();

  const findingRows = findings
    .map(
      (f) =>
        "<tr>" +
        COLUMNS.map((col) => `<td>${htmlEscape(f[col])}</td>`).join("") +
        "</tr>",
    )
    .join("");

  const findingsTable = findings.length
    ? `<table>
         <thead><tr>${COLUMNS.map((col) => `<th>${htmlEscape(COLUMN_LABELS[col] ?? col)}</th>`).join("")}</tr></thead>
         <tbody>${findingRows}</tbody>
       </table>`
    : "<p><em>No findings were recorded for this scan.</em></p>";

  const scopeTable = scope
    ? `<h2>Scan Scope</h2>
       <table>
         <thead><tr><th>Scope</th><th>Path</th></tr></thead>
         <tbody>
           ${scope.inScope.map((p) => `<tr><td>In scope</td><td>${htmlEscape(p)}</td></tr>`).join("")}
           ${scope.outOfScope.map((p) => `<tr><td>Out of scope</td><td>${htmlEscape(p)}</td></tr>`).join("")}
         </tbody>
       </table>`
    : "";

  return `<!DOCTYPE html>
<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word" xmlns="http://www.w3.org/TR/REC-html40">
<head>
  <meta charset="utf-8">
  <title>VulnVista Findings Report</title>
  <style>
    body { font-family: Calibri, Arial, sans-serif; color: #201f1e; font-size: 11pt; }
    h1 { font-size: 20pt; margin-bottom: 4pt; }
    h2 { font-size: 14pt; margin-top: 18pt; border-bottom: 1px solid #aaa6a1; padding-bottom: 2pt; }
    .meta { color: #676360; font-size: 9pt; margin-top: 0; }
    table { border-collapse: collapse; width: 100%; margin-top: 8pt; font-size: 9pt; }
    th, td { border: 1px solid #aaa6a1; padding: 4pt 6pt; text-align: left; vertical-align: top; }
    th { background: #efedea; }
  </style>
</head>
<body>
  <h1>VulnVista Findings Report</h1>
  <p class="meta">Generated ${htmlEscape(generated)} &middot; ${findings.length} finding${findings.length === 1 ? "" : "s"}</p>
  ${scopeTable}
  <h2>Findings</h2>
  ${findingsTable}
</body>
</html>`;
}

export function downloadFindingsReport(
  findings: Finding[],
  format: ReportFormat = "csv",
  scope?: ReportScope,
) {
  const stamp = new Date().toISOString().slice(0, 10);
  const isDoc = format === "doc";
  const content = isDoc ? buildDoc(findings, scope) : buildCsv(findings, scope);
  const blob = new Blob([content], {
    type: isDoc ? "application/msword;charset=utf-8" : "text/csv;charset=utf-8",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `vulnvista-findings-${stamp}.${isDoc ? "doc" : "csv"}`;
  a.click();
  URL.revokeObjectURL(url);
}
