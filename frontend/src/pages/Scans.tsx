import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { api } from "../services/api";
import type { Finding, Scan } from "../types";
import { useAuth } from "../auth/useAuth";

const TERMINAL: Scan["status"][] = ["COMPLETED", "PARTIAL", "FAILED", "CANCELLED"];
const POLL_INTERVAL_MS = 1500;
// ~20 minutes before we stop waiting. vulnerable_services runs a real nmap scan (up to
// a 15-minute internal ceiling against a busy target) plus per-service NVD/searchsploit
// lookups afterward — the other profiles finish in seconds regardless of this ceiling.
const MAX_POLLS = 800;

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

type ProfileId =
  | "command_injection"
  | "weak_auth"
  | "sensitive_files"
  | "vulnerable_services"
  | "weak_tls";
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
    label: "Command Injection",
    targetType: "webapp",
    defaultUrl: "http://dvwa",
    buttonLabel: "Scan for command injection",
    scanningLabel: "Discovering injection points & probing…",
    noFindingLabel: "No command injection detected on this target",
    help:
      "Works against any target: paste its URL and the scanner auto-discovers a form field " +
      "or query parameter to probe, then confirms OS command injection with output-marker " +
      "and time-based signals. Use Advanced below for a login, a session cookie, or an exact " +
      "parameter to target. http://dvwa is a bundled lab target requiring no setup.",
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
  sensitive_files: {
    label: "Sensitive File Exposure (Juice Shop)",
    targetType: "juice-shop",
    defaultUrl: "http://juice-shop:3000",
    buttonLabel: "Scan for exposed sensitive files",
    scanningLabel: "Checking for exposed backups, config, and metadata…",
    noFindingLabel: "No sensitive files exposed on this target",
    help:
      "Enter the target as the backend reaches it on the lab network — e.g. " +
      "http://juice-shop:3000. The scanner checks for directly retrievable backup files, " +
      "configuration files, repository metadata, source maps, and internal documents, " +
      "confirming each against a baseline so the app's fallback page isn't mistaken for a hit.",
  },
  vulnerable_services: {
    label: "Vulnerable Services (Metasploitable2)",
    targetType: "metasploitable2",
    defaultUrl: "http://metasploitable2",
    buttonLabel: "Scan for vulnerable services",
    scanningLabel: "Discovering open ports and fingerprinting services (nmap)…",
    noFindingLabel: "No known-vulnerable services or insecure protocols detected on this target",
    help:
      "Not limited to a single web app — enter any host the backend can reach (e.g. " +
      "http://metasploitable2). Runs an nmap port scan + version fingerprint, then matches " +
      "each service against known CVEs and insecure-by-design protocols (telnet, rsh/rlogin, " +
      "unauthenticated VNC). Only version fingerprints are used as proof — nothing is ever " +
      "exploited on the target. Can take a couple of minutes since it's a real port scan.",
  },
  weak_tls: {
    label: "Weak TLS Configuration",
    targetType: "host",
    defaultUrl: "https://tls-test",
    buttonLabel: "Scan for weak TLS",
    scanningLabel: "Probing TLS protocols, ciphers, and certificate…",
    noFindingLabel: "No weak protocols, ciphers, or certificate issues detected on this target",
    help:
      "Enter any TLS-speaking host the backend can reach, port included if it's not 443 " +
      "(e.g. https://tls-test defaults to :443 — that's the lab target's real port on the " +
      "shared network, not the :8443 it's published as on localhost). Checks for deprecated " +
      "protocols (SSLv2/3, TLSv1.0/1.1), weak cipher suites (NULL/EXPORT/RC4/DES/MD5), " +
      "certificate issues (self-signed, expired, weak signature/key), and known TLS flaws " +
      "(Heartbleed, ROBOT, CCS injection) — every check is a passive protocol probe.",
  },
};

const TRUSTED_HOSTS = new Set([
  "dvwa",
  "juice-shop",
  "vulnvista_dvwa",
  "vulnvista_juice_shop",
  "metasploitable2",
  "vulnvista_metasploitable2",
  "tls-test",
  "vulnvista_tls_test",
  "localhost",
  "127.0.0.1",
]);

// Client-side mirror of the backend's trust list, for UX only (showing/hiding
// the authorization checkbox) — the backend is the actual enforcement point.
function isTrustedHost(rawUrl: string): boolean {
  try {
    return TRUSTED_HOSTS.has(new URL(rawUrl).hostname.toLowerCase());
  } catch {
    return false;
  }
}

function parseCookieHeader(raw: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (key) cookies[key] = value;
  }
  return cookies;
}

export default function Scans() {
  const { canOperate } = useAuth();
  const [scans, setScans] = useState<Scan[]>([]);
  const [profile, setProfile] = useState<ProfileId>("command_injection");
  const [url, setUrl] = useState(PROFILES.command_injection.defaultUrl);
  const [name, setName] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [advUsername, setAdvUsername] = useState("");
  const [advPassword, setAdvPassword] = useState("");
  const [advLoginPath, setAdvLoginPath] = useState("");
  const [advCookie, setAdvCookie] = useState("");
  const [advParameter, setAdvParameter] = useState("");
  const [advPath, setAdvPath] = useState("");
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
    const trusted = isTrustedHost(url);
    try {
      const scanConfig: Record<string, unknown> = {};
      if (advUsername.trim() && advPassword.trim()) {
        scanConfig.username = advUsername.trim();
        scanConfig.password = advPassword.trim();
        if (advLoginPath.trim()) scanConfig.login_path = advLoginPath.trim();
      }
      if (advCookie.trim()) scanConfig.cookies = parseCookieHeader(advCookie.trim());
      if (advParameter.trim()) scanConfig.parameter = advParameter.trim();
      if (advPath.trim()) {
        if (/^https?:\/\//i.test(advPath.trim())) scanConfig.injection_url = advPath.trim();
        else scanConfig.exec_path = advPath.trim();
      }

      const p1 = begin(`Registering target ${url.trim()}…`);
      const target = await api.createTarget({
        name: name.trim() || url.trim(),
        target_type: cfg.targetType,
        base_url: url.trim(),
        environment: "lab",
        authorization_confirmed: authorized,
        ...(Object.keys(scanConfig).length > 0 ? { scan_config: scanConfig } : {}),
      });
      finish(p1, "done", `Target registered: ${target.name}`);

      const p2 = begin("Checking authorization…");
      if (!target.is_allowed) {
        finish(p2, "error", `${url} is not approved for scanning`);
        throw new Error(
          trusted
            ? `${url} could not be approved automatically — please try again.`
            : `${url} isn't a recognized lab host and no authorization was confirmed. Check ` +
              `"I have authorization to test this target" above and try again.`,
        );
      }
      finish(p2, "done", trusted ? "Trusted lab host ✓" : "Authorized by you ✓");

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

      {canOperate ? <form
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
            disabled={busy || (!isTrustedHost(url) && !authorized)}
            className="rounded-md bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? "Scanning…" : PROFILES[profile].buttonLabel}
          </button>
        </div>
        <p className="text-xs text-slate-500">{PROFILES[profile].help}</p>

        {!isTrustedHost(url) && (
          <label className="flex items-center gap-2 text-xs text-slate-300">
            <input
              type="checkbox"
              checked={authorized}
              onChange={(e) => setAuthorized(e.target.checked)}
              className="h-3.5 w-3.5 rounded border-slate-600 bg-slate-950"
            />
            I have authorization to test this target for security vulnerabilities.
          </label>
        )}

        <details className="rounded-md border border-slate-800 bg-slate-950/40 p-3 text-xs text-slate-400">
          <summary className="cursor-pointer select-none text-slate-300">Advanced (optional)</summary>
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            {profile === "command_injection" && (
              <>
                <input
                  type="text"
                  value={advUsername}
                  onChange={(e) => setAdvUsername(e.target.value)}
                  placeholder="Login username"
                  className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-sky-500"
                />
                <input
                  type="password"
                  value={advPassword}
                  onChange={(e) => setAdvPassword(e.target.value)}
                  placeholder="Login password"
                  className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-sky-500"
                />
                <input
                  type="text"
                  value={advLoginPath}
                  onChange={(e) => setAdvLoginPath(e.target.value)}
                  placeholder="Login path (e.g. /login.php)"
                  className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-sky-500"
                />
              </>
            )}
            <input
              type="text"
              value={advCookie}
              onChange={(e) => setAdvCookie(e.target.value)}
              placeholder="Session cookie (name=value; name2=value2)"
              className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-sky-500 sm:col-span-2"
            />
            <input
              type="text"
              value={advParameter}
              onChange={(e) => setAdvParameter(e.target.value)}
              placeholder="Exact parameter name (e.g. ip)"
              className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-sky-500"
            />
            <input
              type="text"
              value={advPath}
              onChange={(e) => setAdvPath(e.target.value)}
              placeholder="Exact injection path or full URL"
              className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-sky-500"
            />
          </div>
          <p className="mt-2">
            Leave everything blank to auto-discover an injectable form field or query
            parameter on the target page. A session cookie is the most reliable way to scan a
            site behind a login that isn't a simple HTML form.
          </p>
        </details>

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
      </form> : (
        <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-4 text-sm text-slate-400">
          Your viewer role has read-only access. Ask an administrator for analyst access to run scans.
        </div>
      )}

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
