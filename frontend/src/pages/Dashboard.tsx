import { Link } from "react-router-dom";
import PageHeader from "../components/PageHeader";
import { useAppData } from "../hooks/useAppData";
import { DETECTORS } from "../lib/detectors";
import { SEVERITY_ORDER } from "../lib/severity";
import { Link } from "react-router-dom";
import { useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import { api } from "../services/api";
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

const severityColor: Record<string, string> = {
  CRITICAL: "bg-red-500/20 text-red-300",
  HIGH: "bg-orange-500/20 text-orange-300",
  MEDIUM: "bg-amber-500/20 text-amber-300",
  LOW: "bg-slate-500/20 text-slate-300",
};

type Activity = {
  id: string;
  message: string;
  status: "SUCCESS" | "ERROR" | "RUNNING";
  timestamp: string;
};

const activityStorageKey = "vulnvista-dashboard-activity";

function formatScanTime(value: string | null) {
  return value
    ? new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
        new Date(value),
      )
    : "Not started";
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
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedTargetId, setSelectedTargetId] = useState("");
  const [newTargetName, setNewTargetName] = useState("");
  const [newTargetUrl, setNewTargetUrl] = useState("");
  const [permissionConfirmed, setPermissionConfirmed] = useState(false);
  const [isAddingTarget, setIsAddingTarget] = useState(false);
  const [activity, setActivity] = useState<Activity[]>(() => {
    try {
      const storedActivity = localStorage.getItem(activityStorageKey);
      return storedActivity ? (JSON.parse(storedActivity) as Activity[]) : [];
    } catch {
      return [];
    }
  });
  const [isScanning, setIsScanning] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function loadDashboard() {
    const [loadedTargets, loadedScans, loadedFindings] = await Promise.all([
      api.listTargets(),
      api.listScans(),
      api.listFindings(),
    ]);
    setTargets(loadedTargets);
    setScans(loadedScans);
    setFindings(loadedFindings);
    setSelectedTargetId((current) => current || loadedTargets.find((target) => target.is_allowed)?.id || "");
  }

  useEffect(() => {
    loadDashboard().catch((err: Error) => setError(err.message));
  }, []);

  useEffect(() => {
    localStorage.setItem(activityStorageKey, JSON.stringify(activity));
  }, [activity]);

  function addActivity(status: Activity["status"], message: string) {
    setActivity((current) => [
      { id: crypto.randomUUID(), message, status, timestamp: new Date().toISOString() },
      ...current,
    ].slice(0, 20));
  }

  const allowedTargets = useMemo(() => targets.filter((target) => target.is_allowed), [targets]);
  const recentFindings = findings.slice(0, 5);
  const recentScans = scans.slice(0, 5);
  const findingCountByScan = useMemo(() => {
    return findings.reduce<Record<string, number>>((counts, finding) => {
      counts[finding.scan_id] = (counts[finding.scan_id] ?? 0) + 1;
      return counts;
    }, {});
  }, [findings]);
  const targetNameById = useMemo(
    () => Object.fromEntries(targets.map((target) => [target.id, target.name])),
    [targets],
  );
  const stats = [
    { label: "Targets", value: targets.length },
    { label: "Scans", value: scans.length },
    { label: "Findings", value: findings.length },
    {
      label: "Critical/High",
      value: findings.filter((finding) => ["CRITICAL", "HIGH"].includes(finding.severity)).length,
    },
  ];

  async function runScan() {
    if (!selectedTargetId) return;

    setIsScanning(true);
    setError(null);
    setMessage(null);
    addActivity("RUNNING", `Started scan for ${targetNameById[selectedTargetId] ?? "approved target"}.`);
    try {
      const scan = await api.createScan({ target_id: selectedTargetId, scan_profile: "default" });
      await loadDashboard();
      setMessage(`Scan completed with status: ${scan.status}.`);
      addActivity("SUCCESS", `Scan for ${targetNameById[selectedTargetId] ?? "approved target"} completed: ${scan.status}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not run the scan.");
      addActivity("ERROR", "Scan could not be completed. See the dashboard error message for details.");
    } finally {
      setIsScanning(false);
    }
  }

  async function addAuthorizedTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setMessage(null);

    let url: URL;
    try {
      url = new URL(newTargetUrl);
    } catch {
      setError("Enter a valid website URL, including http:// or https://.");
      return;
    }

    if (!["http:", "https:"].includes(url.protocol)) {
      setError("Only http and https targets are supported.");
      return;
    }

    setIsAddingTarget(true);
    try {
      const target = await api.createTarget({
        name: newTargetName.trim() || url.hostname,
        target_type: "web",
        base_url: url.origin,
        environment: "authorized",
      });
      await api.allowTarget(target.id);
      await loadDashboard();
      setSelectedTargetId(target.id);
      setNewTargetName("");
      setNewTargetUrl("");
      setPermissionConfirmed(false);
      setMessage(`${target.name} was added as an approved target.`);
      addActivity("SUCCESS", `${target.name} was added as an approved website.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not add the approved target.");
      addActivity("ERROR", "The authorized website could not be added.");
    } finally {
      setIsAddingTarget(false);
    }
  }

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

    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">Dashboard</h1>
          <p className="mt-1 text-sm text-slate-400">Run approved lab scans and review their findings.</p>
        </div>
        <Link className="text-sm text-sky-300 hover:text-sky-200" to="/findings">
          View all findings →
        </Link>
      </div>

      {error && (
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#b91f10] bg-[#fff1ef] px-5 py-3 text-xs text-[#8f190e]">
          <span>Could not refresh the security data: {error}</span>
          <button type="button" onClick={refresh} className="font-black uppercase tracking-wide hover:underline">Try again</button>
        </div>
        <p className="rounded border border-red-800 bg-red-950/50 px-4 py-2 text-sm text-red-300">
          {error}
        </p>
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
      {message && <p className="rounded bg-emerald-500/10 px-4 py-2 text-sm text-emerald-300">{message}</p>}

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {stats.map((stat) => (
          <div key={stat.label} className="rounded-lg border border-slate-800 bg-slate-900 p-4">
            <p className="text-xs uppercase tracking-wide text-slate-400">{stat.label}</p>
            <p className="mt-1 text-2xl font-semibold">{stat.value}</p>
          </div>
        ))}
      </div>

      <section className="rounded-lg border border-slate-800 bg-slate-900 p-5">
        <h2 className="text-lg font-medium">Run a scan</h2>
        <p className="mt-1 text-sm text-slate-400">Only targets on the approved allowlist can be selected.</p>
        <div className="mt-4 flex flex-wrap gap-3">
          <label className="sr-only" htmlFor="scan-target">Approved target</label>
          <select
            className="min-w-64 rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
            id="scan-target"
            value={selectedTargetId}
            onChange={(event) => setSelectedTargetId(event.target.value)}
          >
            {allowedTargets.length === 0 && <option value="">No approved targets available</option>}
            {allowedTargets.map((target) => (
              <option key={target.id} value={target.id}>
                {target.name} ({target.environment})
              </option>
            ))}
          </select>
          <button
            className="rounded bg-sky-500 px-4 py-2 text-sm font-medium text-slate-950 disabled:cursor-not-allowed disabled:opacity-50"
            disabled={!selectedTargetId || isScanning}
            onClick={runScan}
            type="button"
          >
            {isScanning ? "Running scan…" : "Run scan"}
          </button>
        </div>
      </section>

      <section className="rounded-lg border border-slate-800 bg-slate-900 p-5">
        <h2 className="text-lg font-medium">Add an authorized website</h2>
        <p className="mt-1 text-sm text-slate-400">
          External sites receive the passive CSRF check only. Lab-specific probes remain limited to DVWA and Juice Shop.
        </p>
        <form className="mt-4 grid gap-3 sm:grid-cols-2" onSubmit={addAuthorizedTarget}>
          <label className="grid gap-1 text-sm text-slate-300" htmlFor="target-name">
            Website name
            <input
              className="rounded border border-slate-700 bg-slate-950 px-3 py-2"
              id="target-name"
              onChange={(event) => setNewTargetName(event.target.value)}
              placeholder="Example client site"
              value={newTargetName}
            />
          </label>
          <label className="grid gap-1 text-sm text-slate-300" htmlFor="target-url">
            Base URL
            <input
              className="rounded border border-slate-700 bg-slate-950 px-3 py-2"
              id="target-url"
              onChange={(event) => setNewTargetUrl(event.target.value)}
              placeholder="https://example.com"
              required
              type="url"
              value={newTargetUrl}
            />
          </label>
          <label className="flex items-start gap-2 text-sm text-slate-300 sm:col-span-2">
            <input
              checked={permissionConfirmed}
              className="mt-1"
              onChange={(event) => setPermissionConfirmed(event.target.checked)}
              type="checkbox"
            />
            <span>I confirm I have permission to assess this website and will scan only the agreed scope.</span>
          </label>
          <div className="sm:col-span-2">
            <button
              className="rounded bg-sky-500 px-4 py-2 text-sm font-medium text-slate-950 disabled:cursor-not-allowed disabled:opacity-50"
              disabled={!permissionConfirmed || isAddingTarget}
              type="submit"
            >
              {isAddingTarget ? "Adding website…" : "Add approved website"}
            </button>
          </div>
        </form>
      </section>

      <section>
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-lg font-medium">Recent scans</h2>
          <Link className="text-sm text-sky-300 hover:text-sky-200" to="/scans">View all</Link>
        </div>
        <div className="overflow-hidden rounded-lg border border-slate-800">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-900 text-xs uppercase text-slate-400">
              <tr>
                <th className="px-4 py-2">Target</th>
                <th className="px-4 py-2">Status</th>
                <th className="px-4 py-2">Results</th>
                <th className="px-4 py-2">Completed</th>
              </tr>
            </thead>
            <tbody>
              {recentScans.map((scan) => {
                const findingCount = findingCountByScan[scan.id] ?? 0;
                return (
                  <tr key={scan.id} className="border-t border-slate-800">
                    <td className="px-4 py-3">{targetNameById[scan.target_id] ?? "Unknown target"}</td>
                    <td className="px-4 py-3 text-slate-300">{scan.status}</td>
                    <td className="px-4 py-3 text-slate-400">
                      {findingCount === 0
                        ? `No vulnerabilities detected · ${scan.pages_scanned} page${scan.pages_scanned === 1 ? "" : "s"} checked`
                        : `${findingCount} finding${findingCount === 1 ? "" : "s"} · ${scan.pages_scanned} page${scan.pages_scanned === 1 ? "" : "s"} checked`}
                    </td>
                    <td className="px-4 py-3 text-slate-400">{formatScanTime(scan.completed_at)}</td>
                  </tr>
                );
              })}
              {recentScans.length === 0 && (
                <tr>
                  <td className="px-4 py-6 text-center text-slate-500" colSpan={4}>
                    No scans have run yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="rounded-lg border border-slate-800 bg-slate-900 p-5">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-medium">Activity log</h2>
            <p className="mt-1 text-sm text-slate-400">Recent dashboard actions in this browser.</p>
          </div>
          <button
            className="text-sm text-slate-400 hover:text-slate-200"
            onClick={() => setActivity([])}
            type="button"
          >
            Clear log
          </button>
        </div>
        <ol className="mt-4 divide-y divide-slate-800">
          {activity.map((entry) => (
            <li key={entry.id} className="flex flex-wrap items-center justify-between gap-2 py-3 text-sm">
              <div className="flex items-center gap-2">
                <span
                  className={`h-2 w-2 rounded-full ${
                    entry.status === "SUCCESS"
                      ? "bg-emerald-500"
                      : entry.status === "ERROR"
                        ? "bg-red-500"
                        : "bg-amber-500"
                  }`}
                />
                <span>{entry.message}</span>
              </div>
              <time className="text-xs text-slate-500" dateTime={entry.timestamp}>
                {formatScanTime(entry.timestamp)}
              </time>
            </li>
          ))}
          {activity.length === 0 && (
            <li className="py-5 text-center text-sm text-slate-500">No dashboard activity yet.</li>
          )}
        </ol>
      </section>

      <section>
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-lg font-medium">Recent findings</h2>
          <Link className="text-sm text-sky-300 hover:text-sky-200" to="/findings">View all</Link>
        </div>
        <div className="grid gap-3">
          {recentFindings.map((finding) => (
            <article key={finding.id} className="rounded-lg border border-slate-800 bg-slate-950 p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3 className="font-medium">{finding.vulnerability_name}</h3>
                <span className={`rounded px-2 py-0.5 text-xs ${severityColor[finding.severity] ?? "bg-slate-700 text-slate-200"}`}>
                  {finding.severity}
                </span>
              </div>
              <p className="mt-2 break-all text-sm text-slate-400">{finding.affected_endpoint ?? "No endpoint recorded"}</p>
              <p className="mt-2 text-xs text-slate-500">
                {finding.validation_status.replaceAll("_", " ")} · {formatScanTime(finding.created_at)}
              </p>
            </article>
          ))}
          {recentFindings.length === 0 && (
            <p className="rounded-lg border border-dashed border-slate-800 p-6 text-center text-sm text-slate-500">
              No findings yet. Run an approved scan to see the results here.
            </p>
          )}
        </div>
      </section>
    </div>
  );
}
