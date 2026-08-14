import { useEffect, useState } from "react";
import { api } from "../services/api";
import type { Target } from "../types";

function authorizationLabel(t: Target): string {
  if (t.is_allowed && !t.authorization_confirmed) return "Trusted lab host";
  if (t.is_allowed && t.authorization_confirmed) return "Self-declared";
  return "Not approved";
}

export default function Targets() {
  const [targets, setTargets] = useState<Target[]>([]);

  useEffect(() => {
    api.listTargets().then(setTargets).catch(() => setTargets([]));
  }, []);

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Targets</h1>
      <div className="overflow-hidden rounded-lg border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-xs uppercase text-slate-400">
            <tr>
              <th className="px-4 py-2">Name</th>
              <th className="px-4 py-2">Type</th>
              <th className="px-4 py-2">Base URL</th>
              <th className="px-4 py-2">Authorization</th>
            </tr>
          </thead>
          <tbody>
            {targets.map((t) => (
              <tr key={t.id} className="border-t border-slate-800">
                <td className="px-4 py-2">{t.name}</td>
                <td className="px-4 py-2">{t.target_type}</td>
                <td className="px-4 py-2 text-slate-400">{t.base_url ?? "—"}</td>
                <td className="px-4 py-2">{authorizationLabel(t)}</td>
              </tr>
            ))}
            {targets.length === 0 && (
              <tr>
                <td className="px-4 py-6 text-center text-slate-500" colSpan={4}>
                  No targets yet. Add one via the API to get started.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
