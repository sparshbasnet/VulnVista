import type { Finding } from "../types";

export type ReportFormat = "csv" | "doc" | "xls" | "pdf";

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

/** Build a Word- or Excel-openable document (HTML with a .doc/.xls extension).
 * Word, Excel, and Google Docs/Sheets all render this as a formatted report
 * with real tables — no binary file format library required. */
function buildHtmlTable(findings: Finding[], scope: ReportScope | undefined, kind: "word" | "excel"): string {
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

  const xmlns =
    kind === "word"
      ? `xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word"`
      : `xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel"`;

  return `<!DOCTYPE html>
<html ${xmlns} xmlns="http://www.w3.org/TR/REC-html40">
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

/** Build a real PDF file (jsPDF + autotable) with one table per section.
 * Both libraries are dynamically imported so their ~250 kB (gzipped) weight
 * only loads when someone actually picks the PDF format. */
async function buildPdf(findings: Finding[], scope?: ReportScope) {
  const [{ default: jsPDF }, { default: autoTable }] = await Promise.all([
    import("jspdf"),
    import("jspdf-autotable"),
  ]);

  const doc = new jsPDF({ orientation: "landscape" });
  const generated = new Date().toLocaleString();

  doc.setFontSize(16);
  doc.text("VulnVista Findings Report", 14, 16);
  doc.setFontSize(9);
  doc.setTextColor(103, 99, 96);
  doc.text(
    `Generated ${generated} · ${findings.length} finding${findings.length === 1 ? "" : "s"}`,
    14,
    22,
  );

  let cursorY = 28;

  if (scope) {
    autoTable(doc, {
      startY: cursorY,
      head: [["Scope", "Path"]],
      body: [
        ...scope.inScope.map((p) => ["In scope", p]),
        ...scope.outOfScope.map((p) => ["Out of scope", p]),
      ],
      styles: { fontSize: 8 },
      headStyles: { fillColor: [239, 237, 234], textColor: [23, 22, 22] },
      margin: { left: 14, right: 14 },
    });
    cursorY = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 8;
  }

  // Evidence text is long and free-form — cramming it into the main table as
  // just another column starves it of width and the rest of the columns get
  // truncated/squeezed. Drop it from the main table and list it separately
  // below, where it gets the full page width to wrap into.
  const tableColumns = COLUMNS.filter((col) => col !== "evidence_summary");

  autoTable(doc, {
    startY: cursorY,
    head: [tableColumns.map((col) => COLUMN_LABELS[col] ?? col)],
    body: findings.map((f) =>
      tableColumns.map((col) => (f[col] === null || f[col] === undefined ? "" : String(f[col]))),
    ),
    styles: { fontSize: 7, overflow: "linebreak" },
    headStyles: { fillColor: [239, 237, 234], textColor: [23, 22, 22] },
    margin: { left: 14, right: 14 },
  });
  cursorY = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 10;

  if (findings.length) {
    if (cursorY > doc.internal.pageSize.getHeight() - 30) {
      doc.addPage();
      cursorY = 16;
    }
    doc.setFontSize(12);
    doc.setTextColor(23, 22, 22);
    doc.text("Evidence", 14, cursorY);
    cursorY += 6;

    autoTable(doc, {
      startY: cursorY,
      head: [["Vulnerability", "Endpoint", "Evidence"]],
      body: findings.map((f) => [
        String(f.vulnerability_name ?? ""),
        String(f.affected_endpoint ?? ""),
        String(f.evidence_summary ?? ""),
      ]),
      styles: { fontSize: 8, cellWidth: "wrap", overflow: "linebreak" },
      columnStyles: {
        0: { cellWidth: 60 },
        1: { cellWidth: 70 },
        2: { cellWidth: "auto" },
      },
      headStyles: { fillColor: [239, 237, 234], textColor: [23, 22, 22] },
      margin: { left: 14, right: 14 },
    });
  }

  return doc;
}

export async function downloadFindingsReport(
  findings: Finding[],
  format: ReportFormat = "csv",
  scope?: ReportScope,
) {
  const stamp = new Date().toISOString().slice(0, 10);
  const filename = `vulnvista-findings-${stamp}.${format}`;

  if (format === "pdf") {
    const doc = await buildPdf(findings, scope);
    doc.save(filename);
    return;
  }

  const content =
    format === "doc"
      ? buildHtmlTable(findings, scope, "word")
      : format === "xls"
        ? buildHtmlTable(findings, scope, "excel")
        : buildCsv(findings, scope);
  const mimeType =
    format === "doc"
      ? "application/msword;charset=utf-8"
      : format === "xls"
        ? "application/vnd.ms-excel;charset=utf-8"
        : "text/csv;charset=utf-8";

  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
