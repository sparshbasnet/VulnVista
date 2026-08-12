import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { api } from "../services/api";
import type { Finding, Scan } from "../types";

const TERMINAL: Scan["status"][] = ["COMPLETED", "PARTIAL", "FAILED", "CANCELLED"];
const POLL_INTERVAL_MS = 1500;
const MAX_POLLS = 120; // ~3 minutes before we stop waiting

const severityColor: Record<string, string> = {
  CRITICAL: "bg-red-500/20 text-red-300",
  HIGH: "bg-orange-500/20 text-orange-300",
  MEDIUM: "bg-amber-500/20 text-amber-300",
  LOW: "bg-slate-500/20 text-slate-300",
  INFO: "bg-slate-700/40 text-slate-300",
};

type PhaseState = "active" | "done" | "error";
interface Phase {
  label: string;
  state: PhaseState;
}

type ProfileId = "command_injection" | "weak_auth";
interface ProfileConfig {
  label: string;
  targetType: string;
  defaultUrl: string;
  buttonLabel: string;
  scanningLabel: string;
  noFindingLabel: string;
  help: string;
}

const PROFILES: Record<ProfileId, ProfileConfig> = {
  command_injection: {
    label: "Command Injection (DVWA)",
    targetType: "dvwa",
    defaultUrl: "http://dvwa",
    buttonLabel: "Scan for command injection",
    scanningLabel: "Authenticating & injecting probes…",
    noFindingLabel: "No command injection detected on this target",
    help:
      "Enter the target as the backend reaches it on the lab network — e.g. http://dvwa, not " +
      "http://localhost:8081. The scanner logs into DVWA (admin / password), sets security to " +
      "low, and confirms OS command injection with output-marker and time-based probes.",
  },
  weak_auth: {
    label: "Weak Authentication (Juice Shop)",
    targetType: "juice-shop",
    defaultUrl: "http://juice-shop:3000",
    buttonLabel: "Scan for weak authentication",
    scanningLabel: "Probing authentication endpoints…",
    noFindingLabel: "No weak authentication controls detected on this target",
    help:
      "Enter the target as the backend reaches it on the lab network — e.g. " +
      "http://juice-shop:3000. The scanner checks the seeded admin account for username " +
      "enumeration via the password-reset flow and for missing login rate limiting/lockout.",
  },
};

export default function Scans() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [profile, setProfile] = useState<ProfileId>("command_injection");
  const [url, setUrl] = useState(PROFILES.command_injection.defaultUrl);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [phases, setPhases] = useState<Phase[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const cancelled = useRef(false);

  useEffect(() => {
    cancelled.current = false; // reset — StrictMode remounts must not leave this stuck true
    api.listScans().then(setScans).catch(() => setScans([]));
    return () => {
      cancelled.current = true;
    };
  }, []);

  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

  function selectProfile(next: ProfileId) {
    // Only clobber the URL if it's still the previous profile's default —
    // preserves whatever the user typed themselves.
    if (url === PROFILES[profile].defaultUrl) {
      setUrl(PROFILES[next].defaultUrl);
    }
    setProfile(next);
  }

  async function startScan(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setFindings(null);

    // Local, mutable phase list re-rendered after every change — avoids stale
    // state closures while the async flow progresses.
    const list: Phase[] = [];
    const render = () => setPhases([...list]);
    const begin = (label: string) => {
      list.push({ label, state: "active" });
      render();
      return list.length - 1;
    };
    const finish = (i: number, state: PhaseState, label?: string) => {
      list[i] = { label: label ?? list[i].label, state };
      render();
    };
    const relabel = (i: number, label: string) => {
      list[i] = { ...list[i], label };
      render();
    };

    setPhases([]);
    const cfg = PROFILES[profile];
    try {
      const p1 = begin(`Registering target ${url.trim()}…`);
      const target = await api.createTarget({
        name: name.trim() || url.trim(),
        target_type: cfg.targetType,
        base_url: url.trim(),
        environment: "lab",
      });
      finish(p1, "done", `Target registered: ${target.name}`);

      const p2 = begin("Checking scan allowlist…");
      if (!target.is_allowed) {
        finish(p2, "error", `${url} is not on the lab allowlist`);
        throw new Error(
          `${url} is not on the lab allowlist, so it can't be scanned. Use an approved ` +
            `lab host as the backend sees it (e.g. http://dvwa).`,
        );
      }
      finish(p2, "done", "Approved by allowlist ✓");

      const p3 = begin("Launching scan…");
      let current = await api.createScan({
        target_id: target.id,
        scan_profile: profile,
      });
      finish(p3, "done", `Scan ${current.id.slice(0, 8)} launched`);

      const p4 = begin(cfg.scanningLabel);
      const started = Date.now();
      let polls = 0;
      while (!TERMINAL.includes(current.status)) {
        if (cancelled.current) return;
        if (polls++ >= MAX_POLLS) {
          finish(p4, "error", "Timed out waiting for the scan to finish");
          throw new Error("Timed out waiting for the scan to finish.");
        }
        const secs = Math.round((Date.now() - started) / 1000);
        relabel(p4, `Scanning… ${current.status.toLowerCase()} (${secs}s elapsed)`);
        await sleep(POLL_INTERVAL_MS);
        current = await api.getScan(current.id);
      }

      const dur = (current.duration_seconds ?? 0).toFixed(1);
      const ok = current.status === "COMPLETED" || current.status === "PARTIAL";
      finish(p4, ok ? "done" : "error", `Scan ${current.status.toLowerCase()} in ${dur}s`);

      if (current.error_summary) setError(current.error_summary);

      const result = await api.getScanFindings(current.id);
      setFindings(result);
      const p5 = begin(
        result.length > 0
          ? `${result.length} finding(s) recorded — see results below`
          : current.error_summary
            ? "No findings recorded"
            : cfg.noFindingLabel,
      );
      finish(p5, "done");

      api.listScans().then(setScans).catch(() => undefined);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Scans</h1>

      <form
        onSubmit={startScan}
        className="space-y-3 rounded-lg border border-slate-800 bg-slate-900/40 p-4"
      >
        <div className="flex flex-col gap-3 sm:flex-row">
          <select
            value={profile}
            onChange={(e) => selectProfile(e.target.value as ProfileId)}
            className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-sky-500 sm:w-64"
          >
            {(Object.keys(PROFILES) as ProfileId[]).map((id) => (
              <option key={id} value={id}>
                {PROFILES[id].label}
              </option>
            ))}
          </select>
          <input
            type="url"
            required
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder={PROFILES[profile].defaultUrl}
            className="flex-1 rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-sky-500"
          />
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Name (optional)"
            className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-sky-500 sm:w-56"
          />
          <button
            type="submit"
            disabled={busy}
            className="rounded-md bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? "Scanning…" : PROFILES[profile].buttonLabel}
          </button>
        </div>
        <p className="text-xs text-slate-500">{PROFILES[profile].help}</p>

        {(phases.length > 0 || error) && (
          <div className="space-y-2 rounded-md border border-slate-800 bg-slate-950/60 p-3 text-sm">
            {phases.map((p, i) => (
              <div key={i} className="flex items-center gap-2">
                {p.state === "active" && (
                  <span className="h-3.5 w-3.5 shrink-0 animate-spin rounded-full border-2 border-slate-600 border-t-sky-400" />
                )}
                {p.state === "done" && <span className="shrink-0 text-emerald-400">✓</span>}
                {p.state === "error" && <span className="shrink-0 text-red-400">✗</span>}
                <span
                  className={
                    p.state === "error"
                      ? "text-red-400"
                      : p.state === "active"
                        ? "text-sky-300"
                        : "text-slate-300"
                  }
                >
                  {p.label}
                </span>
              </div>
            ))}
            {error && <p className="pt-1 text-red-400">⚠ {error}</p>}
          </div>
        )}
      </form>

      {findings && findings.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-lg font-medium">Scan results</h2>
          {findings.map((f) => (
            <div key={f.id} className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`rounded px-2 py-0.5 text-xs ${severityColor[f.severity] ?? "bg-slate-700/40 text-slate-300"}`}
                >
                  {f.severity}
                </span>
                <span className="font-medium">{f.vulnerability_name}</span>
                <span className="text-xs text-slate-500">
                  {f.cwe} · {f.owasp_category} · {f.validation_status}
                </span>
              </div>
              {f.description && <p className="mt-2 text-sm text-slate-300">{f.description}</p>}
              {f.evidence_summary && (
                <p className="mt-1 font-mono text-xs text-slate-400">{f.evidence_summary}</p>
              )}
              {f.affected_endpoint && (
                <p className="mt-1 text-xs text-slate-500">
                  {f.affected_endpoint} (parameter: {f.parameter ?? "—"})
                </p>
              )}
            </div>
          ))}
        </div>
      )}

      <div className="space-y-2">
        <h2 className="text-lg font-medium">Recent scans</h2>
        <div className="overflow-hidden rounded-lg border border-slate-800">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-900 text-xs uppercase text-slate-400">
              <tr>
                <th className="px-4 py-2">Status</th>
                <th className="px-4 py-2">Profile</th>
                <th className="px-4 py-2">Started</th>
                <th className="px-4 py-2">Duration</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id} className="border-t border-slate-800">
                  <td className="px-4 py-2">{s.status}</td>
                  <td className="px-4 py-2">{s.scan_profile}</td>
                  <td className="px-4 py-2 text-slate-400">{s.started_at ?? "—"}</td>
                  <td className="px-4 py-2 text-slate-400">
                    {s.duration_seconds ? `${s.duration_seconds.toFixed(1)}s` : "—"}
                  </td>
                </tr>
              ))}
              {scans.length === 0 && (
                <tr>
                  <td className="px-4 py-6 text-center text-slate-500" colSpan={4}>
                    No scans yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
