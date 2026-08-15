import { Link } from "react-router-dom";
import PageHeader from "../components/PageHeader";
import { useAppData } from "../hooks/useAppData";
import { DETECTORS } from "../lib/detectors";
import { SEVERITY_ORDER } from "../lib/severity";
import type { Finding, Scan, Target } from "../types";

const severityColor: Record<string, string> = {
  CRITICAL: "#b71f0e",
  HIGH: "#f0321d",
  MEDIUM: "#ff8c7c",
  LOW: "#aaa6a1",
  INFO: "#dedbd7",
};

const severityWeight: Record<string, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

function formatDateTime(value: string | null | undefined): string {
  if (!value) return "Not available";
  return new Intl.DateTimeFormat(undefined, {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

function localDayKey(value: string): string {
  const date = new Date(value);
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
}

function StatCell({
  label,
  value,
  sub,
  signal = false,
}: {
  label: string;
  value: string;
  sub: string;
  signal?: boolean;
}) {
  return (
    <div className="min-h-[124px] bg-[#f7f6f4] p-5">
      <p className="vv-label">{label}</p>
      <p className={`mt-1 text-[clamp(2.25rem,4vw,3.1rem)] font-black leading-none tracking-[-0.055em] ${signal ? "text-[#a61b0d]" : "text-[#171616]"}`}>
        {value}
      </p>
      <p className="mt-2 text-[11px] leading-snug text-[#514e4b]">{sub}</p>
    </div>
  );
}

function SectionHeading({ title, sub, action }: { title: string; sub: string; action?: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 className="text-xs font-black uppercase tracking-[0.1em] text-[#171616]">{title}</h2>
        <p className="mt-1 text-[11px] text-[#676360]">{sub}</p>
      </div>
      {action}
    </div>
  );
}

function SeverityDistribution({ findings }: { findings: Finding[] }) {
  const open = findings.filter((finding) => finding.finding_status === "OPEN");
  const counts = SEVERITY_ORDER.map((severity) => ({
    severity,
    count: open.filter((finding) => finding.severity === severity).length,
  }));
  const total = Math.max(1, open.length);
  const max = Math.max(1, ...counts.map(({ count }) => count));

  return (
    <section className="border-b border-r border-[#aaa6a1] p-5 lg:border-b-0">
      <SectionHeading
        title="Severity distribution"
        sub={`${open.length} open finding records · grouped by severity`}
      />

      <div className="mt-5 flex h-7 overflow-hidden bg-[#e4e1de]" aria-label="Stacked severity distribution">
        {counts.map(({ severity, count }) =>
          count > 0 ? (
            <div
              key={severity}
              style={{ width: `${(count / total) * 100}%`, backgroundColor: severityColor[severity] }}
              title={`${severity}: ${count}`}
            />
          ) : null,
        )}
      </div>

      <div className="mt-5 space-y-3">
        {counts.map(({ severity, count }) => (
          <div key={severity} className="grid grid-cols-[76px_minmax(0,1fr)_24px] items-center gap-3">
            <span className="text-[10px] font-black uppercase tracking-[0.08em]">{severity}</span>
            <div className="h-3 bg-[#e9e7e4]">
              <div
                className="h-full transition-[width]"
                style={{
                  width: `${(count / max) * 100}%`,
                  backgroundColor: severityColor[severity],
                }}
              />
            </div>
            <span className="text-right text-xs font-black">{count}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function ScanOutcomes({ scans }: { scans: Scan[] }) {
  const now = new Date();
  const days = Array.from({ length: 7 }, (_, index) => {
    const date = new Date(now.getFullYear(), now.getMonth(), now.getDate() - (6 - index));
    const key = localDayKey(date.toISOString());
    const dayScans = scans.filter((scan) => {
      const timestamp = scan.completed_at ?? scan.started_at ?? scan.created_at;
      return localDayKey(timestamp) === key;
    });
    const terminalDayScans = dayScans.filter((scan) =>
      ["COMPLETED", "PARTIAL", "FAILED", "CANCELLED"].includes(scan.status),
    );
    return {
      key,
      label: new Intl.DateTimeFormat(undefined, { weekday: "short" }).format(date),
      day: String(date.getDate()),
      completed: terminalDayScans.filter((scan) => scan.status === "COMPLETED").length,
      partial: terminalDayScans.filter((scan) => scan.status === "PARTIAL").length,
      failed: terminalDayScans.filter((scan) => ["FAILED", "CANCELLED"].includes(scan.status)).length,
      total: terminalDayScans.length,
    };
  });
  const max = Math.max(1, ...days.map((day) => day.total));
  const terminal = scans.filter((scan) => ["COMPLETED", "PARTIAL", "FAILED", "CANCELLED"].includes(scan.status));
  const completed = terminal.filter((scan) => scan.status === "COMPLETED").length;
  const successRate = terminal.length ? Math.round((completed / terminal.length) * 100) : 0;

  return (
    <section className="p-5">
      <SectionHeading
        title="Scan outcomes · last 7 days"
        sub={`${completed} completed overall · ${successRate}% terminal success`}
      />

      <div className="mt-5 grid h-[178px] grid-cols-7 gap-2 border-b border-[#77736f] px-1" aria-label="Daily scan outcomes">
        {days.map((day) => (
          <div
            key={day.key}
            className="flex min-w-0 flex-col justify-end text-center"
            role="img"
            aria-label={`${day.label} ${day.day}: ${day.completed} completed, ${day.partial} partial, ${day.failed} failed`}
          >
            <div className="mx-auto flex w-full max-w-9 flex-col justify-end" style={{ height: "128px" }}>
              <div
                className="flex w-full flex-col justify-end"
                style={{ height: day.total ? `${Math.max(7, (day.total / max) * 100)}%` : 0 }}
                title={`${day.label} ${day.day}: ${day.completed} completed, ${day.partial} partial, ${day.failed} failed`}
              >
                {day.failed > 0 && (
                  <div className="bg-[#f0321d]" style={{ flex: day.failed }} aria-hidden="true" />
                )}
                {day.partial > 0 && (
                  <div className="bg-[#ff9b8e]" style={{ flex: day.partial }} aria-hidden="true" />
                )}
                {day.completed > 0 && (
                  <div className="bg-[#2b2928]" style={{ flex: day.completed }} aria-hidden="true" />
                )}
              </div>
            </div>
            <span className="mt-2 truncate text-[9px] font-bold uppercase text-[#676360]">{day.label}</span>
            <span className="text-[9px] text-[#918d88]">{day.day}</span>
          </div>
        ))}
      </div>

      <div className="mt-4 flex flex-wrap gap-x-5 gap-y-2 text-[9px] font-semibold uppercase tracking-wide text-[#514e4b]">
        <span className="flex items-center gap-2"><span className="h-2.5 w-2.5 bg-[#2b2928]" />Completed</span>
        <span className="flex items-center gap-2"><span className="h-2.5 w-2.5 bg-[#ff9b8e]" />Partial</span>
        <span className="flex items-center gap-2"><span className="h-2.5 w-2.5 bg-[#f0321d]" />Failed</span>
      </div>
    </section>
  );
}

function DetectorCoverage({ findings, scans }: { findings: Finding[]; scans: Scan[] }) {
  const implemented = DETECTORS.filter((detector) => detector.key).length;
  const reporting = DETECTORS.filter(
    (detector) => detector.key && findings.some((finding) => finding.detector_id === detector.key),
  ).length;

  return (
    <section className="border-b border-[#aaa6a1]">
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-[#aaa6a1] px-5 py-4">
        <SectionHeading
          title="Detector coverage"
          sub={`${DETECTORS.length} categories · ${implemented} implemented · ${reporting} with recorded findings`}
        />
        <Link to="/scans" className="vv-button-secondary">Run a scan</Link>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5">
        {DETECTORS.map((detector) => {
          const detectorFindings = detector.key
            ? findings.filter((finding) => finding.detector_id === detector.key)
            : [];
          const criticalOpen = detectorFindings.filter(
            (finding) => finding.severity === "CRITICAL" && finding.finding_status === "OPEN",
          ).length;
          const runCount = detector.key
            ? scans.filter((scan) => scan.scan_profile === detector.key).length
            : 0;
          const status = !detector.key
            ? "Planned"
            : detectorFindings.length
              ? `${detectorFindings.length} finding record${detectorFindings.length === 1 ? "" : "s"}`
              : runCount
                ? `${runCount} run${runCount === 1 ? "" : "s"} · no finding record`
                : "No run recorded";

          return (
            <div
              key={detector.n}
              className={`relative min-h-[112px] border-b border-r border-[#aaa6a1] p-4 ${!detector.key ? "bg-[#efedea] text-[#918d88]" : "bg-[#f7f6f4]"}`}
            >
              <div
                className={`absolute inset-x-0 top-0 h-0.5 ${criticalOpen ? "bg-[#f0321d]" : detectorFindings.length ? "bg-[#ff9b8e]" : "bg-transparent"}`}
              />
              <div className="flex items-start justify-between gap-3">
                <span className="font-mono text-[9px] text-[#77736f]">{String(detector.n).padStart(2, "0")}</span>
                <span className={`text-base font-black ${criticalOpen ? "text-[#a61b0d]" : "text-[#aaa6a1]"}`}>
                  {detectorFindings.length || "—"}
                </span>
              </div>
              <h3 className="mt-1 text-xs font-black leading-tight">{detector.title}</h3>
              <p className="mt-1 truncate font-mono text-[9px] text-[#77736f]">{detector.file}</p>
              <p className={`mt-2 text-[9px] font-bold uppercase tracking-[0.08em] ${criticalOpen ? "text-[#a61b0d]" : "text-[#676360]"}`}>
                {criticalOpen ? `${criticalOpen} critical open` : status}
              </p>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function OwaspMapping({ findings }: { findings: Finding[] }) {
  const groups = new Map<string, number>();
  findings
    .filter((finding) => finding.finding_status === "OPEN")
    .forEach((finding) => {
      const label = finding.owasp_category?.trim() || "Unmapped";
      groups.set(label, (groups.get(label) ?? 0) + 1);
    });
  const categories = [...groups.entries()].sort((a, b) => b[1] - a[1]).slice(0, 7);
  const max = Math.max(1, ...categories.map(([, count]) => count));

  return (
    <section className="border-b border-r border-[#aaa6a1] p-5 lg:border-b-0">
      <SectionHeading title="OWASP mapping" sub="Open finding records grouped by category" />
      <div className="mt-5 space-y-4">
        {categories.map(([category, count]) => (
          <div key={category}>
            <div className="flex items-end justify-between gap-3 text-[10px]">
              <span className="min-w-0 truncate font-semibold">{category}</span>
              <span className="font-black">{count}</span>
            </div>
            <div className="mt-1.5 h-2 bg-[#e6e3e0]">
              <div className="h-full bg-[#f0321d]" style={{ width: `${(count / max) * 100}%` }} />
            </div>
          </div>
        ))}
        {categories.length === 0 && <p className="py-8 text-center text-xs text-[#77736f]">No OWASP mappings recorded yet.</p>}
      </div>
    </section>
  );
}

function targetLabel(target: Target | undefined): string {
  return target?.name || target?.base_url || "Unknown target";
}

function HighestRisk({ findings, targets }: { findings: Finding[]; targets: Target[] }) {
  const targetMap = new Map(targets.map((target) => [target.id, target]));
  const highest = findings
    .filter((finding) => finding.finding_status === "OPEN")
    .sort(
      (a, b) =>
        (severityWeight[b.severity] ?? 0) - (severityWeight[a.severity] ?? 0) ||
        (b.cvss_score ?? 0) - (a.cvss_score ?? 0),
    )
    .slice(0, 6);

  return (
    <section className="min-w-0 p-5">
      <SectionHeading
        title="Highest-risk open findings"
        sub="Prioritized by CVSS and severity"
        action={<Link to="/findings" className="text-[10px] font-black uppercase tracking-wide text-[#a61b0d] hover:underline">All findings →</Link>}
      />

      <div className="vv-scrollbar mt-4 overflow-x-auto">
        <table className="vv-table min-w-[620px]">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Vulnerability</th>
              <th>Target</th>
              <th>Evidence</th>
              <th className="text-right">CVSS</th>
            </tr>
          </thead>
          <tbody>
            {highest.map((finding) => (
              <tr key={finding.id}>
                <td>
                  <span className={`inline-flex min-w-[70px] justify-center px-2 py-1 text-[9px] font-black uppercase ${finding.severity === "CRITICAL" ? "bg-[#b71f0e] text-white" : finding.severity === "HIGH" ? "bg-[#d62d18] text-white" : "bg-[#ffd8d2] text-[#a61b0d]"}`}>
                    {finding.severity}
                  </span>
                </td>
                <td>
                  <Link to={`/findings?finding=${finding.id}`} className="font-black hover:text-[#a61b0d]">
                    {finding.vulnerability_name}
                  </Link>
                  <p className="mt-0.5 max-w-[260px] truncate font-mono text-[9px] text-[#676360]">
                    {finding.affected_endpoint || finding.detector_id}
                  </p>
                </td>
                <td className="max-w-[160px] truncate">{targetLabel(targetMap.get(finding.target_id))}</td>
                <td>
                  <span className="font-black">{finding.evidence?.length ?? 0}</span>
                  <span className="ml-1 text-[9px] uppercase text-[#676360]">artifact</span>
                </td>
                <td className="text-right text-sm font-black">{finding.cvss_score?.toFixed(1) ?? "—"}</td>
              </tr>
            ))}
            {highest.length === 0 && (
              <tr><td colSpan={5} className="py-10 text-center text-[#77736f]">No open findings.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default function Dashboard() {
  const { targets, scans, findings, loading, error, refresh } = useAppData();
  const open = findings.filter((finding) => finding.finding_status === "OPEN");
  const critical = open.filter((finding) => finding.severity === "CRITICAL");
  const confirmed = findings.filter((finding) => finding.validation_status === "CONFIRMED");
  const suspected = findings.filter((finding) => finding.validation_status === "SUSPECTED").length;
  const lastScan = scans[0];
  const terminalScans = scans.filter((scan) => ["COMPLETED", "PARTIAL", "FAILED", "CANCELLED"].includes(scan.status));
  const completedScans = terminalScans.filter((scan) => scan.status === "COMPLETED").length;
  const scanSuccess = terminalScans.length ? Math.round((completedScans / terminalScans.length) * 100) : 0;

  return (
    <div className="bg-[#f7f6f4]">
      <PageHeader
        eyebrow="Overview"
        title="Security posture"
        right={
          <>
            <div className="min-w-[170px] px-4 py-1 text-right">
              <p className="vv-label">Last scan</p>
              <p className="mt-1 text-[11px] font-black text-[#171616]">
                {lastScan ? formatDateTime(lastScan.created_at) : "No scans yet"}
              </p>
              {lastScan && <p className="mt-0.5 text-[9px] text-[#676360]">{lastScan.scan_profile.replace(/_/g, " ")}</p>}
            </div>
            <div className="min-w-[112px] px-4 py-1 text-right">
              <p className="vv-label">Open critical</p>
              <p className="mt-1 text-[12px] font-black text-[#a61b0d]">{critical.length} findings</p>
            </div>
          </>
        }
      />

      {error && (
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#b91f10] bg-[#fff1ef] px-5 py-3 text-xs text-[#8f190e]">
          <span>Could not refresh the security data: {error}</span>
          <button type="button" onClick={refresh} className="font-black uppercase tracking-wide hover:underline">Try again</button>
        </div>
      )}
      {loading && findings.length === 0 && (
        <div className="border-b border-[#aaa6a1] px-5 py-4 text-xs font-semibold uppercase tracking-wide text-[#676360]">Loading security data…</div>
      )}

      <section className="grid gap-px border-b border-[#aaa6a1] bg-[#aaa6a1] sm:grid-cols-2 lg:grid-cols-4">
        <StatCell label="Open findings" value={String(open.length)} sub={`across ${targets.length} registered target records`} />
        <StatCell label="Critical severity" value={String(critical.length)} sub="open records · immediate action" signal />
        <StatCell label="Confirmed by probe" value={String(confirmed.length)} sub={`${suspected} suspected awaiting proof`} />
        <StatCell label="Scan success" value={`${scanSuccess}%`} sub={`${completedScans} of ${terminalScans.length} terminal runs completed`} />
      </section>

      <div className="grid border-b border-[#aaa6a1] lg:grid-cols-2">
        <SeverityDistribution findings={findings} />
        <ScanOutcomes scans={scans} />
      </div>

      <DetectorCoverage findings={findings} scans={scans} />

      <div className="grid lg:grid-cols-[minmax(300px,0.8fr)_minmax(0,1.2fr)]">
        <OwaspMapping findings={findings} />
        <HighestRisk findings={findings} targets={targets} />
      </div>
    </div>
  );
}
