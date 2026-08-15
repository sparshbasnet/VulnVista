
import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import FindingCard from "../components/FindingCard";
import PageHeader from "../components/PageHeader";
import { useAppData } from "../hooks/useAppData";
import { api } from "../services/api";
import type { Finding, Scan } from "../types";
import { useAuth } from "../auth/useAuth";

const TERMINAL: Scan["status"][] = ["COMPLETED", "PARTIAL", "FAILED", "CANCELLED"];
const POLL_INTERVAL_MS = 1500;
// ~20 minutes before we stop waiting. vulnerable_services runs a real nmap scan (up to
// a 15-minute internal ceiling against a busy target) plus per-service NVD/searchsploit
// lookups afterward — the other profiles finish in seconds regardless of this ceiling.
const MAX_POLLS = 800;

type PhaseState = "active" | "done" | "error";
interface Phase {
  label: string;
  state: PhaseState;
}
type ProfileId =
  | "command_injection"
  | "sql_injection"
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
  sql_injection: {
    label: "SQL Injection",
    targetType: "webapp",
    defaultUrl: "http://dvwa",
    buttonLabel: "Scan for SQL injection",
    scanningLabel: "Discovering injection points & probing…",
    noFindingLabel: "No SQL injection detected on this target",
    help:
      "Works against any target: paste its URL and the scanner auto-discovers a form field " +
      "or query parameter to probe, then confirms SQL injection with an error-signature, " +
      "boolean-blind, and time-blind signal. Use Advanced below for a login, a session " +
      "cookie, or an exact parameter to target. http://dvwa is a bundled lab target requiring no setup.",
  },
  weak_auth: {
    label: "Weak Authentication",
    targetType: "webapp",
    defaultUrl: "http://juice-shop:3000",
    buttonLabel: "Scan for weak authentication",
    scanningLabel: "Probing authentication endpoints…",
    noFindingLabel: "No weak authentication controls detected on this target",
    help:
      "Works against any target with a login form: paste its URL and the scanner " +
      "auto-discovers the login form, then checks for missing login rate limiting/lockout. " +
      "Provide a known valid username/email in Advanced to also check for account-" +
      "enumeration oracles (skipped otherwise, since a valid account can't be discovered " +
      "safely). http://juice-shop:3000 is a bundled lab target requiring no setup.",
  },
  sensitive_files: {
    label: "Sensitive File Exposure",
    targetType: "webapp",
    defaultUrl: "http://juice-shop:3000",
    buttonLabel: "Scan for exposed sensitive files",
    scanningLabel: "Checking for exposed backups, config, and metadata…",
    noFindingLabel: "No sensitive files exposed on this target",
    help:
      "Works against any target: paste its URL and the scanner checks a generic set of " +
      "well-known backup, environment/config, credential-store, source-map, log, and " +
      "repository-metadata paths (.git, .env, *.js.map, and more), confirming each against " +
      "a baseline so the app's fallback page isn't mistaken for a hit. " +
      "http://juice-shop:3000 is a bundled lab target requiring no setup.",
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
  const { targets: registeredTargets, refresh, replaceFinding } = useAppData();
  const [scans, setScans] = useState<Scan[]>([]);
  const [profile, setProfile] = useState<ProfileId>("command_injection");
  const [url, setUrl] = useState(PROFILES.command_injection.defaultUrl);
  const [name, setName] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [authorizationScope, setAuthorizationScope] = useState("");
  const [selectedTargetId, setSelectedTargetId] = useState("NEW");
  const [advUsername, setAdvUsername] = useState("");
  const [advPassword, setAdvPassword] = useState("");
  const [advLoginPath, setAdvLoginPath] = useState("");
  const [advKnownUsername, setAdvKnownUsername] = useState("");
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

  function upsertScan(next: Scan) {
    setScans((current) => {
      const exists = current.some((scan) => scan.id === next.id);
      return exists
        ? current.map((scan) => (scan.id === next.id ? next : scan))
        : [next, ...current];
    });
  }

  function clearAdvancedOverrides() {
    setAdvUsername("");
    setAdvPassword("");
    setAdvLoginPath("");
    setAdvKnownUsername("");
    setAdvCookie("");
    setAdvParameter("");
    setAdvPath("");
  }

  function selectProfile(next: ProfileId) {
    // Only clobber the URL if it's still the previous profile's default —
    // preserves whatever the user typed themselves.
    if (url === PROFILES[profile].defaultUrl) {
      setUrl(PROFILES[next].defaultUrl);
    }
    setProfile(next);
    setSelectedTargetId("NEW");
    setAuthorized(false);
    setAuthorizationScope("");
    clearAdvancedOverrides();
  }

  function updateUrl(next: string) {
    setUrl(next);
    setSelectedTargetId("NEW");
    setAuthorized(false);
    setAuthorizationScope("");
    clearAdvancedOverrides();
  }

  function chooseRegisteredTarget(id: string) {
    setSelectedTargetId(id);
    if (id === "NEW") return;
    const target = registeredTargets.find((candidate) => candidate.id === id);
    if (!target?.base_url) return;
    setUrl(target.base_url);
    setName(target.name);
    setAuthorized(false);
    setAuthorizationScope("");
    clearAdvancedOverrides();
  }

  function acknowledgeAuthorization(checked: boolean) {
    setAuthorized(checked);
    setAuthorizationScope(checked ? url.trim() : "");
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
    const existingTarget = selectedTargetId === "NEW"
      ? undefined
      : registeredTargets.find((candidate) => candidate.id === selectedTargetId);
    const labTrusted = isTrustedHost(url);
    try {
      const scanConfig: Record<string, unknown> = {};
      if (advUsername.trim() && advPassword.trim()) {
        scanConfig.username = advUsername.trim();
        scanConfig.password = advPassword.trim();
      }
      if (advLoginPath.trim()) scanConfig.login_path = advLoginPath.trim();
      if (advKnownUsername.trim()) scanConfig.known_username = advKnownUsername.trim();
      if (advCookie.trim()) scanConfig.cookies = parseCookieHeader(advCookie.trim());
      if (advParameter.trim()) scanConfig.parameter = advParameter.trim();
      if (advPath.trim()) {
        if (/^https?:\/\//i.test(advPath.trim())) scanConfig.injection_url = advPath.trim();
        else if (profile === "sql_injection") scanConfig.injection_path = advPath.trim();
        else scanConfig.exec_path = advPath.trim();
      }

      const p1 = begin(existingTarget ? `Using target ${existingTarget.name}…` : `Registering target ${url.trim()}…`);
      const target = existingTarget ?? await api.createTarget({
          name: name.trim() || url.trim(),
          target_type: cfg.targetType,
          base_url: url.trim(),
          environment: "lab",
          authorization_confirmed: authorized && authorizationScope === url.trim(),
          ...(Object.keys(scanConfig).length > 0 ? { scan_config: scanConfig } : {}),
        });
      finish(p1, "done", existingTarget ? `Target reused: ${target.name}` : `Target registered: ${target.name}`);

      const p2 = begin("Checking authorization…");
      if (!target.is_allowed) {
        finish(p2, "error", `${url} is not approved for scanning`);
        throw new Error(
          labTrusted
            ? `${url} could not be approved automatically — please try again.`
            : `${url} isn't a recognized lab host and no authorization was confirmed. Check ` +
              `"I have authorization to test this target" above and try again.`,
        );
      }
      finish(
        p2,
        "done",
        labTrusted
          ? existingTarget ? "Trusted lab target reused ✓" : "Trusted lab host ✓"
          : existingTarget ? "Authorized target reused ✓" : "Authorized by you ✓",
      );

      const p3 = begin("Launching scan…");
      let current = await api.createScan({
        target_id: target.id,
        scan_profile: profile,
      });
      upsertScan(current);
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
        upsertScan(current);
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
      void refresh();
    }
  }

  const activeScans = scans.filter((scan) => scan.status === "QUEUED" || scan.status === "RUNNING").length;
  const selectedRegisteredTarget = selectedTargetId === "NEW"
    ? undefined
    : registeredTargets.find((target) => target.id === selectedTargetId);
  const canScanTarget = Boolean(
    selectedRegisteredTarget?.is_allowed || isTrustedHost(url) || authorizationScope === url.trim(),
  );

  return (
    <div className="bg-[#f7f6f4]">
      <PageHeader
        eyebrow="Scanner control"
        title="Run security scans"
        description="Select a detector, confirm the authorized target, and follow each phase from registration to evidence capture."
        right={
          <>
            <div className="px-4 py-1 text-right">
              <p className="vv-label">Active</p>
              <p className="mt-1 text-sm font-black text-[#a61b0d]">{activeScans}</p>
            </div>
            <div className="px-4 py-1 text-right">
              <p className="vv-label">Total runs</p>
              <p className="mt-1 text-sm font-black">{scans.length}</p>
            </div>
          </>
        }
      />

      {canOperate ? (
      <section className="border-b border-[#aaa6a1] p-4 sm:p-5 lg:p-6">
        <form onSubmit={startScan} className="border border-[#8f8b87] bg-[#f7f6f4]">
          <div className="flex flex-wrap items-start justify-between gap-4 border-b border-[#aaa6a1] bg-[#efedea] p-4">
            <div>
              <p className="vv-kicker">New authorized run</p>
              <h2 className="mt-1 text-lg font-black tracking-[-0.03em]">{PROFILES[profile].label}</h2>
            </div>
            <span className="bg-[#171616] px-2.5 py-1.5 font-mono text-[9px] font-bold uppercase text-white">
              detector / {profile}
            </span>
          </div>

          <div className="grid lg:grid-cols-[280px_minmax(0,1fr)]">
            <div className="border-b border-[#aaa6a1] p-4 lg:border-r lg:border-b-0">
              <label>
                <span className="vv-label">Detector profile</span>
                <select
                  value={profile}
                  onChange={(event) => selectProfile(event.target.value as ProfileId)}
                  className="vv-input mt-2 font-bold"
                >
                  {(Object.keys(PROFILES) as ProfileId[]).map((id) => (
                    <option key={id} value={id}>{PROFILES[id].label}</option>
                  ))}
                </select>
              </label>
              <p className="mt-3 text-[10px] leading-relaxed text-[#676360]">{PROFILES[profile].help}</p>
              <div className="mt-5 border-l-2 border-[#f0321d] pl-3">
                <p className="text-[9px] font-black uppercase tracking-[0.08em]">Safe scanning boundary</p>
                <p className="mt-1 text-[9px] leading-relaxed text-[#676360]">
                  Bundled lab hosts are trusted automatically. Every other host requires your explicit authorization.
                </p>
              </div>
            </div>

            <div className="space-y-4 p-4 sm:p-5">
              <label>
                <span className="vv-label">Reuse authorized target · optional</span>
                <select value={selectedTargetId} onChange={(event) => chooseRegisteredTarget(event.target.value)} className="vv-input mt-2 font-bold">
                  <option value="NEW">Register a new target record</option>
                  {registeredTargets.filter((target) => target.is_allowed && target.base_url).map((target) => (
                    <option key={target.id} value={target.id}>{target.name} · {target.base_url}</option>
                  ))}
                </select>
              </label>
              <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_240px]">
                <label>
                  <span className="vv-label">Target URL</span>
                  <input
                    type="url"
                    required
                    value={url}
                    onChange={(event) => updateUrl(event.target.value)}
                    placeholder={PROFILES[profile].defaultUrl}
                    className="vv-input mt-2 font-mono"
                  />
                </label>
                <label>
                  <span className="vv-label">Target name · optional</span>
                  <input
                    type="text"
                    value={name}
                    onChange={(event) => setName(event.target.value)}
                    placeholder="e.g. DVWA lab"
                    className="vv-input mt-2"
                  />
                </label>
              </div>

              {!isTrustedHost(url) && !selectedRegisteredTarget?.is_allowed && (
                <label className="flex items-start gap-3 border border-[#f0a39a] bg-[#fff0ed] p-3 text-[10px] leading-relaxed text-[#76180e]">
                  <input
                    type="checkbox"
                    checked={authorized}
                    onChange={(event) => acknowledgeAuthorization(event.target.checked)}
                    className="mt-0.5 h-4 w-4 shrink-0 accent-[#f0321d]"
                  />
                  <span>
                    <strong className="block text-[9px] uppercase tracking-wide">Authorization required</strong>
                    I have permission to test this target for security vulnerabilities.
                  </span>
                </label>
              )}

              <details className="border border-[#aaa6a1] bg-[#efedea]">
                <summary className="flex min-h-11 items-center justify-between px-3 text-[10px] font-black uppercase tracking-[0.08em]">
                  Advanced probe configuration
                  <span className="text-[#a61b0d]">＋</span>
                </summary>
                <fieldset disabled={Boolean(selectedRegisteredTarget)} className="grid gap-3 border-t border-[#aaa6a1] p-3 disabled:opacity-50 sm:grid-cols-2">
                  {(profile === "command_injection" || profile === "sql_injection") && (
                    <>
                      <input aria-label="Login username" type="text" value={advUsername} onChange={(event) => setAdvUsername(event.target.value)} placeholder="Login username" className="vv-input" />
                      <input aria-label="Login password" type="password" value={advPassword} onChange={(event) => setAdvPassword(event.target.value)} placeholder="Login password" className="vv-input" />
                      <input aria-label="Login path" type="text" value={advLoginPath} onChange={(event) => setAdvLoginPath(event.target.value)} placeholder="Login path (e.g. /login.php)" className="vv-input sm:col-span-2" />
                    </>
                  )}
                  {profile === "weak_auth" && (
                    <>
                      <input aria-label="Login path override" type="text" value={advLoginPath} onChange={(event) => setAdvLoginPath(event.target.value)} placeholder="Login path override (e.g. /login) — leave blank to auto-discover" className="vv-input sm:col-span-2" />
                      <input aria-label="Known valid username or email" type="text" value={advKnownUsername} onChange={(event) => setAdvKnownUsername(event.target.value)} placeholder="Known valid username/email (optional — enables enumeration check)" className="vv-input sm:col-span-2" />
                    </>
                  )}
                  <input aria-label="Session cookie" type="text" value={advCookie} onChange={(event) => setAdvCookie(event.target.value)} placeholder="Session cookie (name=value; name2=value2)" className="vv-input sm:col-span-2" />
                  <input aria-label="Exact parameter name" type="text" value={advParameter} onChange={(event) => setAdvParameter(event.target.value)} placeholder="Exact parameter name (e.g. ip)" className="vv-input" />
                  <input aria-label="Exact injection path or URL" type="text" value={advPath} onChange={(event) => setAdvPath(event.target.value)} placeholder="Exact injection path or full URL" className="vv-input" />
                  <p className="text-[9px] leading-relaxed text-[#676360] sm:col-span-2">
                    {selectedRegisteredTarget
                      ? "This run reuses the authorization and stored scan configuration of the selected target. Register a new target to change these overrides."
                      : "Leave these blank for automatic discovery. Session cookies are the most reliable option for targets behind non-standard login flows."}
                  </p>
                </fieldset>
              </details>

              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[#d0ccc7] pt-4">
                <p className="text-[9px] font-bold uppercase tracking-wide text-[#676360]">
                  Output: finding record + structured evidence
                </p>
                <button
                  type="submit"
            disabled={busy || !canScanTarget}
                  className="vv-button-primary min-w-[190px]"
                >
                  {busy ? "Scan in progress…" : PROFILES[profile].buttonLabel}
                </button>
              </div>
            </div>
          </div>

          {(phases.length > 0 || error) && (
            <div className="border-t border-[#8f8b87] bg-[#201f1e] p-4 text-[#f3f0ed]" role="status" aria-live="polite">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <p className="text-[9px] font-black uppercase tracking-[0.1em] text-[#ff8c7c]">Run console</p>
                <span className="font-mono text-[9px] text-[#aaa6a1]">{phases.length} phases recorded</span>
              </div>
              <div className="mt-3 space-y-2">
                {phases.map((phase, index) => (
                  <div key={index} className="grid grid-cols-[18px_minmax(0,1fr)] items-start gap-2 font-mono text-[10px]">
                    <span
                      className={
                        phase.state === "active"
                          ? "mt-0.5 h-3 w-3 animate-pulse border border-[#ff8c7c] bg-[#f0321d]"
                          : phase.state === "done"
                            ? "text-emerald-400"
                            : "text-[#ff8c7c]"
                      }
                    >
                      {phase.state === "done" ? "✓" : phase.state === "error" ? "×" : ""}
                    </span>
                    <span className={phase.state === "error" ? "text-[#ff8c7c]" : phase.state === "active" ? "text-white" : "text-[#cfcbc7]"}>
                      {phase.label}
                    </span>
                  </div>
                ))}
                {error && <p role="alert" className="border-l-2 border-[#f0321d] pl-3 font-mono text-[10px] text-[#ff8c7c]">{error}</p>}
              </div>
            </div>
          )}
        </form>
      </section>
      ) : (
        <div className="mx-4 mt-4 border border-[#aaa6a1] bg-[#efedea] p-4 text-[10px] leading-relaxed text-[#676360] sm:mx-5 lg:mx-6">
          Your viewer role has read-only access. Ask an administrator for analyst access to run scans.
        </div>
      )}

      {findings && findings.length > 0 && (
        <section className="border-b border-[#aaa6a1] p-4 sm:p-5 lg:p-6">
          <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
            <div>
              <p className="vv-kicker">Latest run</p>
              <h2 className="mt-1 text-lg font-black tracking-[-0.03em]">Captured findings</h2>
            </div>
            <span className="text-[10px] font-black uppercase tracking-wide text-[#a61b0d]">{findings.length} observed</span>
          </div>
          <div className="space-y-2">
            {findings.map((finding) => (
              <FindingCard key={finding.id} finding={finding} defaultExpanded={findings.length === 1} onStatusChange={replaceFinding} />
            ))}
          </div>
        </section>
      )}

      <section className="p-4 sm:p-5 lg:p-6">
        <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
          <div>
            <p className="vv-kicker">History</p>
            <h2 className="mt-1 text-lg font-black tracking-[-0.03em]">Recent scan runs</h2>
          </div>
          <p className="text-[9px] font-bold uppercase tracking-wide text-[#676360]">Newest first</p>
        </div>
        <div className="vv-scrollbar overflow-x-auto border border-[#aaa6a1]">
          <table className="vv-table min-w-[760px] bg-[#f7f6f4]">
            <thead>
              <tr>
                <th>Status</th>
                <th>Profile</th>
                <th>Started</th>
                <th>Duration</th>
                <th>Error summary</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr key={scan.id}>
                  <td>
                    <span
                      className={
                        scan.status === "COMPLETED"
                          ? "inline-flex bg-[#e5f3eb] px-2 py-1 text-[9px] font-black uppercase text-[#167249]"
                          : scan.status === "FAILED" || scan.status === "CANCELLED"
                            ? "inline-flex bg-[#ffd8d2] px-2 py-1 text-[9px] font-black uppercase text-[#a61b0d]"
                            : scan.status === "RUNNING" || scan.status === "QUEUED"
                              ? "inline-flex bg-[#171616] px-2 py-1 text-[9px] font-black uppercase text-white"
                              : "inline-flex bg-[#fff0d8] px-2 py-1 text-[9px] font-black uppercase text-[#8a5508]"
                      }
                    >
                      {scan.status}
                    </span>
                  </td>
                  <td className="font-bold">{scan.scan_profile.replace(/_/g, " ")}</td>
                  <td className="text-[#676360]">
                    {scan.started_at
                      ? new Intl.DateTimeFormat(undefined, { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }).format(new Date(scan.started_at))
                      : "—"}
                  </td>
                  <td className="font-mono text-[10px]">{scan.duration_seconds ? scan.duration_seconds.toFixed(1) + "s" : "—"}</td>
                  <td className="max-w-[300px] truncate text-[10px] text-[#676360]" title={scan.error_summary ?? undefined}>{scan.error_summary ?? "—"}</td>
                </tr>
              ))}
              {scans.length === 0 && (
                <tr><td colSpan={5} className="py-12 text-center text-[#676360]">No scan runs recorded yet.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
