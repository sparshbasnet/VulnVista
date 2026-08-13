import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../services/api";
import { STATUS_OPTIONS } from "../lib/severity";
import type { Finding, FindingStatus } from "../types";
import EvidenceViewer from "./EvidenceViewer";

const severityTone: Record<string, string> = {
  CRITICAL: "bg-[#b71f0e] text-white",
  HIGH: "bg-[#d62d18] text-white",
  MEDIUM: "bg-[#ffb2a8] text-[#76180e]",
  LOW: "bg-[#d5d1cd] text-[#393634]",
  INFO: "bg-[#e8e5e1] text-[#514e4b]",
};

const statusTone: Record<FindingStatus, string> = {
  OPEN: "text-[#b91f10]",
  IN_PROGRESS: "text-[#a95d00]",
  REMEDIATED: "text-[#167249]",
  ACCEPTED_RISK: "text-[#5d557b]",
  FALSE_POSITIVE: "text-[#676360]",
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

export default function FindingCard({
  finding,
  targetLabel,
  defaultExpanded = false,
  onStatusChange,
}: {
  finding: Finding;
  targetLabel?: string;
  defaultExpanded?: boolean;
  onStatusChange?: (updated: Finding) => void;
}) {
  const [expanded, setExpanded] = useState(defaultExpanded);
  const [current, setCurrent] = useState(finding);
  const [saving, setSaving] = useState(false);
  const [statusError, setStatusError] = useState<string | null>(null);
  const evidence = [...(current.evidence ?? [])].sort(
    (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
  );

  useEffect(() => setCurrent(finding), [finding]);
  useEffect(() => {
    if (defaultExpanded) setExpanded(true);
  }, [defaultExpanded]);

  async function changeStatus(next: FindingStatus) {
    if (next === current.finding_status) return;
    setSaving(true);
    setStatusError(null);
    try {
      const updated = await api.updateFindingStatus(current.id, next);
      setCurrent(updated);
      onStatusChange?.(updated);
    } catch (err) {
      setStatusError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <article className={`border bg-[#f7f6f4] ${expanded ? "border-[#171616]" : "border-[#aaa6a1]"}`}>
      <button
        type="button"
        onClick={() => setExpanded((value) => !value)}
        className="grid w-full grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3 px-4 py-3.5 text-left transition-colors hover:bg-white sm:grid-cols-[82px_minmax(180px,1.3fr)_minmax(120px,0.7fr)_90px_auto]"
        aria-expanded={expanded}
      >
        <span className={`inline-flex min-w-[70px] justify-center px-2 py-1 text-[9px] font-black uppercase tracking-[0.06em] ${severityTone[current.severity] ?? severityTone.INFO}`}>
          {current.severity}
        </span>
        <span className="min-w-0">
          <span className="block truncate text-xs font-black text-[#171616] sm:text-sm">{current.vulnerability_name}</span>
          <span className="mt-0.5 block truncate font-mono text-[9px] text-[#676360]">{current.affected_endpoint || current.detector_id}</span>
        </span>
        <span className="hidden min-w-0 sm:block">
          <span className="block truncate text-[10px] font-bold text-[#514e4b]">{targetLabel || "Target unavailable"}</span>
          <span className="mt-0.5 block text-[9px] uppercase tracking-wide text-[#918d88]">{humanize(current.validation_status)}</span>
        </span>
        <span className={`hidden text-[9px] font-black uppercase tracking-[0.07em] sm:block ${statusTone[current.finding_status]}`}>
          {humanize(current.finding_status)}
        </span>
        <span className="flex shrink-0 items-center gap-2 text-[9px] font-bold uppercase text-[#676360]">
          <span>{evidence.length} evidence</span>
          <span className={`text-sm transition-transform ${expanded ? "rotate-45" : ""}`} aria-hidden="true">＋</span>
        </span>
      </button>

      {expanded && (
        <div className="border-t border-[#aaa6a1]">
          <div className="grid border-b border-[#aaa6a1] lg:grid-cols-[minmax(0,1.5fr)_minmax(260px,0.5fr)]">
            <div className="border-b border-[#aaa6a1] p-4 lg:border-r lg:border-b-0">
              <p className="vv-label">Finding summary</p>
              <p className="mt-2 max-w-3xl text-xs leading-relaxed text-[#514e4b]">
                {current.description || current.evidence_summary || "No written description was recorded."}
              </p>
              {current.evidence_summary && current.description && (
                <p className="mt-3 border-l-2 border-[#f0321d] pl-3 font-mono text-[10px] leading-relaxed text-[#514e4b]">
                  {current.evidence_summary}
                </p>
              )}

              <dl className="mt-4 grid gap-px border border-[#d0ccc7] bg-[#d0ccc7] sm:grid-cols-2 xl:grid-cols-4">
                {[
                  ["CVSS", current.cvss_score?.toFixed(1) ?? "—"],
                  ["CWE / CVE", [current.cwe, current.cve].filter(Boolean).join(" · ") || "—"],
                  ["Confidence", current.confidence],
                  ["OWASP", current.owasp_category || "Unmapped"],
                ].map(([label, value]) => (
                  <div key={label} className="bg-white p-3">
                    <dt className="vv-label">{label}</dt>
                    <dd className="mt-1.5 break-words text-[10px] font-black">{value}</dd>
                  </div>
                ))}
              </dl>
            </div>

            <div className="p-4">
              <p className="vv-label">Workflow status</p>
              <select
                value={current.finding_status}
                disabled={saving}
                onChange={(event) => changeStatus(event.target.value as FindingStatus)}
                className="vv-input mt-2 font-bold uppercase"
                aria-label={`Workflow status for ${current.vulnerability_name}`}
              >
                {STATUS_OPTIONS.map((status) => (
                  <option key={status} value={status}>{humanize(status)}</option>
                ))}
              </select>
              <p className="mt-2 min-h-4 text-[9px] leading-relaxed text-[#676360]">
                {saving ? "Saving status…" : `Record updated ${formatDate(current.updated_at ?? current.created_at)}. Earlier status events are not stored.`}
              </p>
              {statusError && <p className="mt-2 text-[10px] font-bold text-[#b91f10]">{statusError}</p>}
            </div>
          </div>

          <div className="grid gap-px border-b border-[#aaa6a1] bg-[#d0ccc7] sm:grid-cols-3">
            <div className="bg-[#f7f6f4] p-4">
              <p className="vv-label">01 · Detected</p>
              <p className="mt-1.5 text-[10px] font-black">{formatDate(current.created_at)}</p>
            </div>
            <div className="bg-[#f7f6f4] p-4">
              <p className="vv-label">02 · Scanner validation</p>
              <p className={`mt-1.5 text-[10px] font-black ${current.validation_status === "CONFIRMED" ? "text-[#f0321d]" : "text-[#514e4b]"}`}>
                {humanize(current.validation_status)}
              </p>
            </div>
            <div className="bg-[#f7f6f4] p-4">
              <p className="vv-label">03 · Human workflow</p>
              <p className={`mt-1.5 text-[10px] font-black ${statusTone[current.finding_status]}`}>{humanize(current.finding_status)}</p>
            </div>
          </div>

          {current.remediation && (
            <div className="border-b border-[#aaa6a1] bg-[#edf7f1] p-4">
              <p className="text-[9px] font-black uppercase tracking-[0.1em] text-[#167249]">Recommended remediation</p>
              <p className="mt-2 text-xs leading-relaxed text-[#24553e]">{current.remediation}</p>
            </div>
          )}

          <div className="p-4">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="vv-label">Evidence artifacts</p>
                <p className="mt-1 text-[10px] text-[#676360]">Stored detector evidence captured by {humanize(current.detector_id)}</p>
              </div>
              <Link to={`/evidence?finding=${current.id}`} className="text-[9px] font-black uppercase tracking-[0.08em] text-[#f0321d] hover:underline">
                Open evidence workspace →
              </Link>
            </div>
            {evidence.length > 0 ? (
              <div className="space-y-3">
                {evidence.map((artifact, index) => (
                  <section key={artifact.id}>
                    <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2 text-[9px] uppercase tracking-wide text-[#676360]">
                      <span className="font-black">Artifact {String(index + 1).padStart(2, "0")} · {humanize(artifact.evidence_type)}</span>
                      <time>{formatDate(artifact.created_at)}</time>
                    </div>
                    <EvidenceViewer content={artifact.content} detectorId={current.detector_id} />
                  </section>
                ))}
              </div>
            ) : (
              <div className="border border-dashed border-[#aaa6a1] px-4 py-8 text-center text-xs text-[#676360]">No structured evidence is attached to this finding.</div>
            )}
          </div>
        </div>
      )}
    </article>
  );
}
