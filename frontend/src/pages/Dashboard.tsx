import { useEffect, useState } from "react";
import { api } from "../services/api";
import type { Finding, Scan, Target } from "../types";

export default function Dashboard() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([api.listTargets(), api.listScans(), api.listFindings()])
      .then(([t, s, f]) => {
        setTargets(t);
        setScans(s);
        setFindings(f);
      })
      .catch((err: Error) => setError(err.message));
  }, []);

  const stats = [
    { label: "Targets", value: targets.length },
    { label: "Scans", value: scans.length },
    { label: "Findings", value: findings.length },
    {
      label: "Critical/High",
      value: findings.filter((f) => ["CRITICAL", "HIGH"].includes(f.severity)).length,
    },
  ];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Dashboard</h1>
      {error && (
        <p className="rounded border border-red-800 bg-red-950/50 px-4 py-2 text-sm text-red-300">
          Could not reach the API: {error}
        </p>
      )}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {stats.map((stat) => (
          <div key={stat.label} className="rounded-lg border border-slate-800 bg-slate-900 p-4">
            <p className="text-xs uppercase tracking-wide text-slate-400">{stat.label}</p>
            <p className="mt-1 text-2xl font-semibold">{stat.value}</p>
          </div>
        ))}
      </div>
      <p className="text-sm text-slate-400">
        Vulnerability detectors, evidence, and remediation workflows land here as they're
        implemented — see the implementation plan for the full milestone roadmap.
      </p>
    </div>
  );
}
