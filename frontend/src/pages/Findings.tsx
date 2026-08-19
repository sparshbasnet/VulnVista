import { useEffect, useState } from "react";
import { api } from "../services/api";
import type { Finding } from "../types";

const severityColor: Record<string, string> = {
  CRITICAL: "bg-red-500/20 text-red-300",
  HIGH: "bg-orange-500/20 text-orange-300",
  MEDIUM: "bg-amber-500/20 text-amber-300",
  LOW: "bg-slate-500/20 text-slate-300",
};

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

export default function Findings() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .listFindings()
      .then(setFindings)
      .catch(() => setError("Could not load findings. Check that the API is running."));
  }, []);

  const highPriority = findings.filter((f) => ["CRITICAL", "HIGH"].includes(f.severity)).length;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Scan findings</h1>
        <p className="mt-1 text-sm text-slate-400">
          {findings.length === 0
            ? "No scan output is available yet."
            : `${findings.length} finding${findings.length === 1 ? "" : "s"} saved, including ${highPriority} high-priority item${highPriority === 1 ? "" : "s"}.`}
        </p>
      </div>

      {error && <p className="rounded-lg bg-red-500/10 p-4 text-sm text-red-300">{error}</p>}

      <div className="grid gap-4">
        {findings.map((finding) => (
          <article key={finding.id} className="rounded-lg border border-slate-800 bg-slate-950 p-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h2 className="text-lg font-medium">{finding.vulnerability_name}</h2>
                <p className="mt-1 text-sm text-slate-400">
                  Detected by {finding.detector_id.replaceAll("_", " ")} · {formatDate(finding.created_at)}
                </p>
              </div>
              <div className="flex gap-2 text-xs font-medium">
                <span
                  className={`rounded px-2 py-1 ${severityColor[finding.severity] ?? "bg-slate-700/40 text-slate-300"}`}
                >
                  {finding.severity}
                </span>
                <span className="rounded bg-slate-800 px-2 py-1 text-slate-200">
                  {finding.validation_status.replaceAll("_", " ")}
                </span>
              </div>
            </div>

            <dl className="mt-5 grid gap-4 text-sm sm:grid-cols-2">
              <div>
                <dt className="text-slate-500">Affected endpoint</dt>
                <dd className="mt-1 break-all text-slate-200">{finding.affected_endpoint ?? "Not recorded"}</dd>
              </div>
              <div>
                <dt className="text-slate-500">Confidence</dt>
                <dd className="mt-1 text-slate-200">{finding.confidence}</dd>
              </div>
              <div>
                <dt className="text-slate-500">Classification</dt>
                <dd className="mt-1 text-slate-200">
                  {[finding.cwe, finding.owasp_category].filter(Boolean).join(" · ") || "Not recorded"}
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">CVSS score</dt>
                <dd className="mt-1 text-slate-200">{finding.cvss_score ?? "Not scored"}</dd>
              </div>
            </dl>

            {finding.remediation && (
              <div className="mt-5 rounded-md bg-slate-900 p-4 text-sm">
                <p className="font-medium text-slate-200">Recommended fix</p>
                <p className="mt-1 leading-6 text-slate-400">{finding.remediation}</p>
              </div>
            )}
          </article>
        ))}

        {!error && findings.length === 0 && (
          <p className="rounded-lg border border-dashed border-slate-800 p-8 text-center text-sm text-slate-500">
            No findings yet. Run a scan against an approved target to populate this view.
          </p>
        )}
      </div>
    </div>
  );
}
