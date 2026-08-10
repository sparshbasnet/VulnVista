import { useEffect, useState } from "react";
import { api } from "../services/api";
import type { Finding } from "../types";

const severityColor: Record<string, string> = {
  CRITICAL: "bg-red-500/20 text-red-300",
  HIGH: "bg-orange-500/20 text-orange-300",
  MEDIUM: "bg-amber-500/20 text-amber-300",
  LOW: "bg-slate-500/20 text-slate-300",
};

export default function Findings() {
  const [findings, setFindings] = useState<Finding[]>([]);

  useEffect(() => {
    api.listFindings().then(setFindings).catch(() => setFindings([]));
  }, []);

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Findings</h1>
      <div className="overflow-hidden rounded-lg border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-xs uppercase text-slate-400">
            <tr>
              <th className="px-4 py-2">Vulnerability</th>
              <th className="px-4 py-2">Severity</th>
              <th className="px-4 py-2">Confidence</th>
              <th className="px-4 py-2">Validation</th>
              <th className="px-4 py-2">CWE</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id} className="border-t border-slate-800">
                <td className="px-4 py-2">{f.vulnerability_name}</td>
                <td className="px-4 py-2">
                  <span
                    className={`rounded px-2 py-0.5 text-xs ${severityColor[f.severity] ?? "bg-slate-700/40 text-slate-300"}`}
                  >
                    {f.severity}
                  </span>
                </td>
                <td className="px-4 py-2 text-slate-400">{f.confidence}</td>
                <td className="px-4 py-2 text-slate-400">{f.validation_status}</td>
                <td className="px-4 py-2 text-slate-400">{f.cwe ?? "—"}</td>
              </tr>
            ))}
            {findings.length === 0 && (
              <tr>
                <td className="px-4 py-6 text-center text-slate-500" colSpan={5}>
                  No findings yet. Run a scan against an approved target to populate this view.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
