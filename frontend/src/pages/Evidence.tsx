import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import EvidenceViewer from "../components/EvidenceViewer";
import PageHeader from "../components/PageHeader";
import { useAppData } from "../hooks/useAppData";
import { api } from "../services/api";
import type { Finding, FindingStatus } from "../types";

const severityTone: Record<string, string> = {
  CRITICAL: "bg-[#b71f0e] text-white",
  HIGH: "bg-[#d62d18] text-white",
  MEDIUM: "bg-[#ffb2a8] text-[#76180e]",
  LOW: "bg-[#d5d1cd] text-[#393634]",
  INFO: "bg-[#e8e5e1] text-[#514e4b]",
};

function humanize(value: string): string {
  return value.replace(/_/g, " ");
}

function formatDate(value: string | null | undefined): string {
  if (!value) return "Not recorded";
  return new Intl.DateTimeFormat(undefined, {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

function ProofStat({ label, value, signal = false }: { label: string; value: number; signal?: boolean }) {
  return (
    <div className="bg-[#f7f6f4] p-4">
      <p className="vv-label">{label}</p>
      <p className={`mt-1 text-2xl font-black tracking-[-0.04em] ${signal ? "text-[#a61b0d]" : "text-[#171616]"}`}>{value}</p>
    </div>
  );
}

export default function Evidence() {
  const { findings, targets, scans, loading, error, refresh, replaceFinding } = useAppData();
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedId = searchParams.get("finding");
  const [query, setQuery] = useState("");
  const [detector, setDetector] = useState("ALL");
  const [selectedId, setSelectedId] = useState<string | null>(requestedId);
  const [savingFindingId, setSavingFindingId] = useState<string | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const detailRef = useRef<HTMLElement>(null);

  const evidenceFindings = useMemo(
    () => findings.filter((finding) => (finding.evidence?.length ?? 0) > 0),
    [findings],
  );
  const targetMap = useMemo(() => new Map(targets.map((target) => [target.id, target])), [targets]);
  const scanMap = useMemo(() => new Map(scans.map((scan) => [scan.id, scan])), [scans]);
  const detectors = useMemo(
    () => [...new Set(evidenceFindings.map((finding) => finding.detector_id))].sort(),
    [evidenceFindings],
  );

  const visible = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return evidenceFindings.filter((finding) => {
      const target = targetMap.get(finding.target_id);
      const haystack = [
        finding.vulnerability_name,
        finding.detector_id,
        finding.evidence_summary,
        finding.affected_endpoint,
        target?.name,
        target?.base_url,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return (!normalized || haystack.includes(normalized)) && (detector === "ALL" || finding.detector_id === detector);
    });
  }, [evidenceFindings, query, detector, targetMap]);

  useEffect(() => {
    if (requestedId && visible.some((finding) => finding.id === requestedId)) {
      setSelectedId(requestedId);
      return;
    }
    if (!selectedId || !visible.some((finding) => finding.id === selectedId)) {
      setSelectedId(visible[0]?.id ?? null);
    }
  }, [requestedId, visible, selectedId]);

  const selected = visible.find((finding) => finding.id === selectedId) ?? null;
  const selectedTarget = selected ? targetMap.get(selected.target_id) : undefined;
  const selectedScan = selected ? scanMap.get(selected.scan_id) : undefined;
  const series = selected
    ? evidenceFindings
        .filter(
          (finding) =>
            finding.target_id === selected.target_id &&
            finding.detector_id === selected.detector_id &&
            finding.vulnerability_name === selected.vulnerability_name &&
            finding.affected_endpoint === selected.affected_endpoint &&
            finding.parameter === selected.parameter,
        )
        .sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())
    : [];

  const artifactCount = evidenceFindings.reduce((total, finding) => total + (finding.evidence?.length ?? 0), 0);
  const confirmedCount = evidenceFindings.filter((finding) => finding.validation_status === "CONFIRMED").length;
  const targetCount = new Set(evidenceFindings.map((finding) => finding.target_id)).size;

  function selectFinding(id: string) {
    setSelectedId(id);
    setStatusError(null);
    setSearchParams({ finding: id });
    window.requestAnimationFrame(() => {
      if (window.matchMedia("(max-width: 1279px)").matches) {
        detailRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
        detailRef.current?.focus({ preventScroll: true });
      }
    });
  }

  async function changeStatus(finding: Finding, status: FindingStatus) {
    if (status === finding.finding_status) return;
    setSavingFindingId(finding.id);
    setStatusError(null);
    try {
      const updated = await api.updateFindingStatus(finding.id, status);
      replaceFinding(updated);
    } catch (err) {
      setStatusError(err instanceof Error ? err.message : String(err));
    } finally {
      setSavingFindingId(null);
    }
  }

  return (
    <div className="bg-[#f7f6f4]">
      <PageHeader
        eyebrow="Evidence library"
        title="Evidence workspace"
        description="Inspect the stored detector evidence behind each finding, with readable summaries and raw data on demand."
        right={
          <div className="px-4 py-1 text-right">
            <p className="vv-label">Artifacts</p>
            <p className="mt-1 text-sm font-black text-[#a61b0d]">{artifactCount}</p>
          </div>
        }
      />

      {error && (
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#b91f10] bg-[#fff1ef] px-5 py-3 text-xs text-[#8f190e]">
          <span>Evidence could not be refreshed: {error}</span>
          <button type="button" onClick={refresh} className="font-black uppercase tracking-wide hover:underline">Try again</button>
        </div>
      )}

      <section className="grid grid-cols-2 gap-px border-b border-[#aaa6a1] bg-[#aaa6a1] sm:grid-cols-4">
        <ProofStat label="Artifacts" value={artifactCount} signal />
        <ProofStat label="Probe confirmed" value={confirmedCount} />
        <ProofStat label="Detector sources" value={detectors.length} />
        <ProofStat label="Target records" value={targetCount} />
      </section>

      <div className="grid min-h-[calc(100vh-250px)] xl:grid-cols-[340px_minmax(0,1fr)]">
        <aside className="border-b border-[#aaa6a1] bg-[#efedea] xl:border-r xl:border-b-0">
          <div className="border-b border-[#aaa6a1] p-4">
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search evidence…"
              className="vv-input"
              aria-label="Search evidence"
            />
            <select value={detector} onChange={(event) => setDetector(event.target.value)} className="vv-input mt-2 font-bold uppercase" aria-label="Filter by detector">
              <option value="ALL">All detector sources</option>
              {detectors.map((value) => <option key={value} value={value}>{humanize(value)}</option>)}
            </select>
            <p className="mt-3 text-[9px] font-bold uppercase tracking-wide text-[#676360]">{visible.length} finding records with evidence</p>
          </div>

          <div className="vv-scrollbar max-h-[300px] overflow-auto xl:max-h-[calc(100vh-364px)]">
            {visible.map((finding) => {
              const target = targetMap.get(finding.target_id);
              const active = finding.id === selected?.id;
              return (
                <button
                  key={finding.id}
                  type="button"
                  disabled={savingFindingId !== null}
                  onClick={() => selectFinding(finding.id)}
                  className={`block w-full border-b border-[#c8c4bf] p-4 text-left transition-colors disabled:cursor-wait ${active ? "bg-white shadow-[inset_3px_0_0_#f0321d]" : "hover:bg-[#f7f6f4]"}`}
                  aria-pressed={active}
                >
                  <div className="flex items-center justify-between gap-3">
                    <span className={`px-2 py-1 text-[8px] font-black uppercase tracking-wide ${severityTone[finding.severity] ?? severityTone.INFO}`}>{finding.severity}</span>
                    <span className="text-[9px] font-black text-[#676360]">{finding.evidence?.length ?? 0} artifact</span>
                  </div>
                  <p className="mt-2 truncate text-xs font-black">{finding.vulnerability_name}</p>
                  <p className="mt-1 truncate font-mono text-[9px] text-[#676360]">{target?.name || target?.base_url || "Unknown target"}</p>
                  <p className="mt-2 text-[8px] font-bold uppercase tracking-[0.08em] text-[#918d88]">{humanize(finding.detector_id)} · {formatDate(finding.created_at)}</p>
                </button>
              );
            })}
            {!loading && visible.length === 0 && <p className="px-4 py-10 text-center text-xs text-[#676360]">No evidence matches these filters.</p>}
            {loading && evidenceFindings.length === 0 && <p className="px-4 py-10 text-center text-xs text-[#676360]">Loading evidence…</p>}
          </div>
        </aside>

        <section ref={detailRef} tabIndex={-1} className="min-w-0 scroll-mt-28 outline-none">
          {selected ? (
            <>
              <section className="border-b border-[#aaa6a1] p-4 sm:p-6">
                <div className="flex flex-wrap items-start justify-between gap-5">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`px-2 py-1 text-[8px] font-black uppercase tracking-wide ${severityTone[selected.severity] ?? severityTone.INFO}`}>{selected.severity}</span>
                      <span className="bg-[#ece9e6] px-2 py-1 text-[8px] font-black uppercase tracking-wide text-[#514e4b]">{humanize(selected.validation_status)}</span>
                    </div>
                    <h2 className="mt-3 text-xl font-black tracking-[-0.035em] sm:text-2xl">{selected.vulnerability_name}</h2>
                    <p className="mt-2 max-w-3xl text-xs leading-relaxed text-[#514e4b]">{selected.evidence_summary || selected.description || "No evidence summary was recorded."}</p>
                  </div>
                  <Link to={`/findings?finding=${selected.id}`} className="vv-button-secondary">Open finding</Link>
                </div>

                <dl className="mt-5 grid gap-px border border-[#d0ccc7] bg-[#d0ccc7] sm:grid-cols-2 lg:grid-cols-4">
                  {[
                    ["Target", selectedTarget?.name || selectedTarget?.base_url || "Unknown"],
                    ["Scan", selectedScan ? `${humanize(selectedScan.scan_profile)} · ${selectedScan.status}` : selected.scan_id.slice(0, 8)],
                    ["Endpoint", selected.affected_endpoint || "Not recorded"],
                    ["Captured", formatDate(selected.created_at)],
                  ].map(([label, value]) => (
                    <div key={label} className="min-w-0 bg-white p-3">
                      <dt className="vv-label">{label}</dt>
                      <dd className="mt-1.5 truncate text-[10px] font-black" title={value}>{value}</dd>
                    </div>
                  ))}
                </dl>
              </section>

              <section className="grid border-b border-[#aaa6a1] lg:grid-cols-[minmax(0,1fr)_280px]">
                <div className="border-b border-[#aaa6a1] p-4 sm:p-5 lg:border-r lg:border-b-0">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <h3 className="text-xs font-black uppercase tracking-[0.1em]">Observation history</h3>
                      <p className="mt-1 text-[10px] leading-relaxed text-[#676360]">Exact same target record, detector, vulnerability, endpoint, and parameter.</p>
                    </div>
                    <span className="text-[10px] font-black text-[#a61b0d]">{series.length} observation{series.length === 1 ? "" : "s"}</span>
                  </div>
                  <div className="vv-scrollbar mt-4 flex overflow-x-auto pb-2">
                    {series.map((observation, index) => (
                      <div key={observation.id} className="relative min-w-[150px] border-t border-[#77736f] pt-4 pr-4">
                        <span className={`absolute -top-[5px] left-0 h-2.5 w-2.5 border-2 border-[#f7f6f4] ${observation.id === selected.id ? "bg-[#f0321d]" : "bg-[#2b2928]"}`} />
                        <p className="text-[9px] font-black uppercase">{index === 0 ? "Earliest stored" : "Later stored"}</p>
                        <p className="mt-1 text-[9px] text-[#676360]">{formatDate(observation.created_at)}</p>
                        <p className="mt-1 text-[8px] font-bold uppercase text-[#918d88]">{humanize(observation.validation_status)}</p>
                      </div>
                    ))}
                  </div>
                  <p className="mt-2 border-l-2 border-[#aaa6a1] pl-3 text-[9px] leading-relaxed text-[#676360]">
                    This is an observation trail, not a remediation audit. Clean detector results and historical status events are not stored, so absence is never labeled “fixed.”
                  </p>
                </div>

                <div className="bg-[#efedea] p-4 sm:p-5">
                  <p className="vv-label">Current workflow state</p>
                  <select
                    value={selected.finding_status}
                    onChange={(event) => changeStatus(selected, event.target.value as FindingStatus)}
                    disabled={savingFindingId !== null}
                    className="vv-input mt-2 font-bold uppercase"
                  >
                    <option value="OPEN">Open</option>
                    <option value="IN_PROGRESS">In progress</option>
                    <option value="REMEDIATED">Remediated</option>
                    <option value="ACCEPTED_RISK">Accepted risk</option>
                    <option value="FALSE_POSITIVE">False positive</option>
                  </select>
                  <p className="mt-2 text-[9px] leading-relaxed text-[#676360]">
                    {savingFindingId === selected.id ? "Saving…" : `Record updated ${formatDate(selected.updated_at ?? selected.created_at)}. Workflow state is separate from scanner validation.`}
                  </p>
                  {statusError && <p className="mt-2 text-[9px] font-bold text-[#b91f10]">{statusError}</p>}
                </div>
              </section>

              <section className="space-y-5 p-4 sm:p-6">
                <div>
                  <h3 className="text-xs font-black uppercase tracking-[0.1em]">Captured evidence</h3>
                  <p className="mt-1 text-[10px] text-[#676360]">Readable detector summary first; full JSON is collapsed until requested.</p>
                </div>
                {(selected.evidence ?? []).map((artifact, index) => (
                  <article key={artifact.id}>
                    <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                      <p className="text-[9px] font-black uppercase tracking-[0.08em]">Artifact {String(index + 1).padStart(2, "0")} · {humanize(artifact.evidence_type)}</p>
                      <time className="text-[9px] text-[#676360]">{formatDate(artifact.created_at)}</time>
                    </div>
                    <EvidenceViewer content={artifact.content} detectorId={selected.detector_id} />
                  </article>
                ))}
              </section>
            </>
          ) : (
            <div className="flex min-h-[420px] items-center justify-center p-8 text-center">
              <div>
                <p className="text-sm font-black">No evidence selected</p>
                <p className="mt-1 text-xs text-[#676360]">Choose an evidence-backed finding from the list.</p>
              </div>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
