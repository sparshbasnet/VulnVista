import { useEffect, useState } from "react";
import { api } from "../services/api";
import type { Scan } from "../types";

export default function Scans() {
  const [scans, setScans] = useState<Scan[]>([]);

  useEffect(() => {
    api.listScans().then(setScans).catch(() => setScans([]));
  }, []);

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Scans</h1>
      <div className="overflow-hidden rounded-lg border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-xs uppercase text-slate-400">
            <tr>
              <th className="px-4 py-2">Status</th>
              <th className="px-4 py-2">Profile</th>
              <th className="px-4 py-2">Started</th>
              <th className="px-4 py-2">Pages</th>
              <th className="px-4 py-2">Duration</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.id} className="border-t border-slate-800">
                <td className="px-4 py-2">{s.status}</td>
                <td className="px-4 py-2">{s.scan_profile}</td>
                <td className="px-4 py-2 text-slate-400">{s.started_at ?? "—"}</td>
                <td className="px-4 py-2 text-slate-400">{s.pages_scanned}</td>
                <td className="px-4 py-2 text-slate-400">
                  {s.duration_seconds !== null ? `${s.duration_seconds.toFixed(1)}s` : "—"}
                </td>
              </tr>
            ))}
            {scans.length === 0 && (
              <tr>
                <td className="px-4 py-6 text-center text-slate-500" colSpan={5}>
                  No scans yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
