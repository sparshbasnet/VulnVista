import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import PageHeader from "../components/PageHeader";
import { useAppData } from "../hooks/useAppData";
import type { Target } from "../types";

function authorizationLabel(target: Target): string {
  if (target.is_allowed && !target.authorization_confirmed) return "Trusted lab";
  if (target.is_allowed && target.authorization_confirmed) return "Self-declared";
  return "Not approved";
}

function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  return new Intl.DateTimeFormat(undefined, { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }).format(new Date(value));
}

function Stat({ label, value, signal = false }: { label: string; value: number; signal?: boolean }) {
  return (
    <div className="bg-[#f7f6f4] p-4">
      <p className="vv-label">{label}</p>
      <p className={`mt-1 text-2xl font-black tracking-[-0.04em] ${signal ? "text-[#a61b0d]" : "text-[#171616]"}`}>{value}</p>
    </div>
  );
}

export default function Targets() {
  const { targets, scans, findings, loading, error, refresh } = useAppData();
  const [query, setQuery] = useState("");
  const normalized = query.trim().toLowerCase();
  const visible = useMemo(
    () =>
      targets.filter((target) =>
        [target.name, target.base_url, target.ip_address, target.target_type, target.environment]
          .filter(Boolean)
          .join(" ")
          .toLowerCase()
          .includes(normalized),
      ),
    [targets, normalized],
  );
  const allowed = targets.filter((target) => target.is_allowed).length;
  const withOpenRisk = new Set(findings.filter((finding) => finding.finding_status === "OPEN").map((finding) => finding.target_id)).size;
  const environments = new Set(targets.map((target) => target.environment)).size;
  const maxOpenFindings = Math.max(
    1,
    ...targets.map(
      (target) => findings.filter((finding) => finding.target_id === target.id && finding.finding_status === "OPEN").length,
    ),
  );

  return (
    <div className="bg-[#f7f6f4]">
      <PageHeader
        eyebrow="Asset scope"
        title="Registered targets"
        description="Every target is kept as an authorization-scoped record. Scan activity and observed risk are shown alongside it."
        right={<Link to="/scans" className="vv-button-primary mx-4 self-center">Register & scan</Link>}
      />

      {error && (
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#b91f10] bg-[#fff1ef] px-5 py-3 text-xs text-[#8f190e]">
          <span>Targets could not be refreshed: {error}</span>
          <button type="button" onClick={refresh} className="font-black uppercase tracking-wide hover:underline">Try again</button>
        </div>
      )}

      <section className="grid grid-cols-2 gap-px border-b border-[#aaa6a1] bg-[#aaa6a1] sm:grid-cols-4">
        <Stat label="Target records" value={targets.length} />
        <Stat label="Approved" value={allowed} />
        <Stat label="With open risk" value={withOpenRisk} signal />
        <Stat label="Environments" value={environments} />
      </section>

      <section className="border-b border-[#aaa6a1] bg-[#efedea] p-4 sm:p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <input
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search target, URL, type, environment…"
            className="vv-input max-w-xl"
          />
          <p className="text-[9px] font-bold uppercase tracking-wide text-[#676360]">{visible.length} of {targets.length} records</p>
        </div>
      </section>

      <section className="p-4 sm:p-5 lg:p-6">
        <div className="vv-scrollbar overflow-x-auto border border-[#aaa6a1]">
          <table className="vv-table min-w-[850px] bg-[#f7f6f4]">
            <thead>
              <tr>
                <th>Target</th>
                <th>Type / environment</th>
                <th>Authorization</th>
                <th>Risk load</th>
                <th>Scans</th>
                <th>Last activity</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((target) => {
                const targetFindings = findings.filter((finding) => finding.target_id === target.id);
                const open = targetFindings.filter((finding) => finding.finding_status === "OPEN").length;
                const targetScans = scans.filter((scan) => scan.target_id === target.id);
                const last = targetScans[0];
                return (
                  <tr key={target.id}>
                    <td>
                      <p className="font-black">{target.name}</p>
                      <p className="mt-1 max-w-[280px] truncate font-mono text-[9px] text-[#676360]" title={target.base_url ?? target.ip_address ?? undefined}>{target.base_url ?? target.ip_address ?? "No endpoint"}</p>
                    </td>
                    <td>
                      <p className="text-[10px] font-bold uppercase">{target.target_type}</p>
                      <p className="mt-1 text-[9px] uppercase text-[#676360]">{target.environment}</p>
                    </td>
                    <td>
                      <span className={`inline-flex px-2 py-1 text-[9px] font-black uppercase ${target.is_allowed ? "bg-[#e5f3eb] text-[#167249]" : "bg-[#ffd8d2] text-[#a61b0d]"}`}>
                        {authorizationLabel(target)}
                      </span>
                    </td>
                    <td>
                      <div className="flex items-center gap-3">
                        <div className="h-2 w-24 bg-[#e4e1de]"><div className="h-full bg-[#f0321d]" style={{ width: `${(open / maxOpenFindings) * 100}%` }} /></div>
                        <span className="text-[10px] font-black">{open} open</span>
                      </div>
                    </td>
                    <td className="font-black">{targetScans.length}</td>
                    <td>
                      <p className="text-[10px] font-bold">{formatDate(last?.created_at ?? target.created_at)}</p>
                      <p className="mt-1 text-[9px] uppercase text-[#676360]">{last?.status ?? "Registered"}</p>
                    </td>
                  </tr>
                );
              })}
              {!loading && visible.length === 0 && (
                <tr><td colSpan={6} className="py-12 text-center text-[#676360]">No targets match this search.</td></tr>
              )}
              {loading && targets.length === 0 && (
                <tr><td colSpan={6} className="py-12 text-center text-[#676360]">Loading targets…</td></tr>
              )}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-[9px] leading-relaxed text-[#676360]">
          A target record represents a specific authorization context. Similar URLs are not merged automatically because credentials and scan configuration may differ.
        </p>
      </section>
    </div>
  );
}
