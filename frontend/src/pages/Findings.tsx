import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import FindingCard from "../components/FindingCard";
import PageHeader from "../components/PageHeader";
import { useAppData } from "../hooks/useAppData";
import type { Finding } from "../types";

const severityWeight: Record<string, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };

function MiniStat({ label, value, tone = false }: { label: string; value: number; tone?: boolean }) {
  return (
    <div className="bg-[#f7f6f4] p-4">
      <p className="vv-label">{label}</p>
      <p className={`mt-1 text-2xl font-black tracking-[-0.04em] ${tone ? "text-[#a61b0d]" : "text-[#171616]"}`}>{value}</p>
    </div>
  );
}

export default function Findings() {
  const { findings, targets, loading, error, refresh, replaceFinding } = useAppData();
  const [searchParams] = useSearchParams();
  const requestedFinding = searchParams.get("finding");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [status, setStatus] = useState("ALL");
  const [validation, setValidation] = useState("ALL");
  const [sort, setSort] = useState("RISK");

  const targetMap = useMemo(() => new Map(targets.map((target) => [target.id, target])), [targets]);
  const filtered = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return findings
      .filter((finding) => {
        const target = targetMap.get(finding.target_id);
        const haystack = [
          finding.vulnerability_name,
          finding.detector_id,
          finding.affected_endpoint,
          finding.cwe,
          finding.cve,
          finding.owasp_category,
          target?.name,
          target?.base_url,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        return (
          (!normalized || haystack.includes(normalized)) &&
          (severity === "ALL" || finding.severity === severity) &&
          (status === "ALL" || finding.finding_status === status) &&
          (validation === "ALL" || finding.validation_status === validation)
        );
      })
      .sort((a, b) => {
        if (sort === "RECENT") return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
        if (sort === "EVIDENCE") return (b.evidence?.length ?? 0) - (a.evidence?.length ?? 0);
        return (
          (severityWeight[b.severity] ?? 0) - (severityWeight[a.severity] ?? 0) ||
          (b.cvss_score ?? 0) - (a.cvss_score ?? 0) ||
          new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
        );
      });
  }, [findings, query, severity, status, validation, sort, targetMap]);

  const open = findings.filter((finding) => finding.finding_status === "OPEN").length;
  const inProgress = findings.filter((finding) => finding.finding_status === "IN_PROGRESS").length;
  const remediated = findings.filter((finding) => finding.finding_status === "REMEDIATED").length;
  const confirmed = findings.filter((finding) => finding.validation_status === "CONFIRMED").length;
  const hasFilters = query || severity !== "ALL" || status !== "ALL" || validation !== "ALL";

  function clearFilters() {
    setQuery("");
    setSeverity("ALL");
    setStatus("ALL");
    setValidation("ALL");
  }

  return (
    <div className="bg-[#f7f6f4]">
      <PageHeader
        eyebrow="Triage"
        title="Vulnerability findings"
        description="Prioritize scanner observations, inspect their evidence, and move each record through the remediation workflow."
        right={
          <div className="px-4 py-1 text-right">
            <p className="vv-label">Finding records</p>
            <p className="mt-1 text-sm font-black">{findings.length}</p>
          </div>
        }
      />

      {error && (
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#b91f10] bg-[#fff1ef] px-5 py-3 text-xs text-[#8f190e]">
          <span>Findings could not be refreshed: {error}</span>
          <button type="button" onClick={refresh} className="font-black uppercase tracking-wide hover:underline">Try again</button>
        </div>
      )}

      <section className="grid grid-cols-2 gap-px border-b border-[#aaa6a1] bg-[#aaa6a1] sm:grid-cols-4">
        <MiniStat label="Open" value={open} tone />
        <MiniStat label="In progress" value={inProgress} />
        <MiniStat label="Remediated" value={remediated} />
        <MiniStat label="Probe confirmed" value={confirmed} />
      </section>

      <section className="border-b border-[#aaa6a1] bg-[#efedea] p-4 sm:p-5">
        <div className="grid gap-2 md:grid-cols-[minmax(180px,1fr)_150px_170px_170px_140px]">
          <label className="min-w-0">
            <span className="sr-only">Search findings</span>
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search finding, endpoint, target, CWE…"
              className="vv-input"
            />
          </label>
          <label>
            <span className="sr-only">Severity</span>
            <select value={severity} onChange={(event) => setSeverity(event.target.value)} className="vv-input font-bold uppercase">
              <option value="ALL">All severities</option>
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((value) => <option key={value}>{value}</option>)}
            </select>
          </label>
          <label>
            <span className="sr-only">Workflow status</span>
            <select value={status} onChange={(event) => setStatus(event.target.value)} className="vv-input font-bold uppercase">
              <option value="ALL">All workflow states</option>
              <option value="OPEN">Open</option>
              <option value="IN_PROGRESS">In progress</option>
              <option value="REMEDIATED">Remediated</option>
              <option value="ACCEPTED_RISK">Accepted risk</option>
              <option value="FALSE_POSITIVE">False positive</option>
            </select>
          </label>
          <label>
            <span className="sr-only">Validation status</span>
            <select value={validation} onChange={(event) => setValidation(event.target.value)} className="vv-input font-bold uppercase">
              <option value="ALL">All validation states</option>
              <option value="CONFIRMED">Confirmed</option>
              <option value="SUSPECTED">Suspected</option>
              <option value="INCONCLUSIVE">Inconclusive</option>
              <option value="ERROR">Error</option>
            </select>
          </label>
          <label>
            <span className="sr-only">Sort findings</span>
            <select value={sort} onChange={(event) => setSort(event.target.value)} className="vv-input font-bold uppercase">
              <option value="RISK">Risk first</option>
              <option value="RECENT">Most recent</option>
              <option value="EVIDENCE">Most evidence</option>
            </select>
          </label>
        </div>
        <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
          <p className="text-[10px] font-bold uppercase tracking-wide text-[#676360]">
            Showing <span className="text-[#171616]">{filtered.length}</span> of {findings.length} records
          </p>
          {hasFilters && (
            <button type="button" onClick={clearFilters} className="text-[9px] font-black uppercase tracking-wide text-[#a61b0d] hover:underline">Clear filters</button>
          )}
        </div>
      </section>

      <section className="space-y-2 p-4 sm:p-5 lg:p-6">
        {loading && findings.length === 0 && (
          <div className="border border-[#aaa6a1] px-4 py-10 text-center text-xs font-bold uppercase tracking-wide text-[#676360]">Loading findings…</div>
        )}
        {filtered.map((finding: Finding) => {
          const target = targetMap.get(finding.target_id);
          return (
            <FindingCard
              key={finding.id}
              finding={finding}
              targetLabel={target?.name || target?.base_url || "Unknown target"}
              defaultExpanded={requestedFinding === finding.id}
              onStatusChange={replaceFinding}
            />
          );
        })}
        {!loading && filtered.length === 0 && (
          <div className="border border-dashed border-[#aaa6a1] px-4 py-14 text-center">
            <p className="text-sm font-black">No findings match this view.</p>
            <p className="mt-1 text-xs text-[#676360]">Adjust the filters or run another authorized scan.</p>
            {hasFilters && <button type="button" onClick={clearFilters} className="vv-button-secondary mt-5">Clear filters</button>}
          </div>
        )}
      </section>
    </div>
  );
}
