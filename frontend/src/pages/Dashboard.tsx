import { Link } from "react-router-dom";
import { useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import { api } from "../services/api";
import type { Finding, Scan, Target } from "../types";

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
        <p className="rounded border border-red-800 bg-red-950/50 px-4 py-2 text-sm text-red-300">
          {error}
        </p>
      )}
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
