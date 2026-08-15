import { useState } from "react";

type DataObject = Record<string, unknown>;

function isObject(value: unknown): value is DataObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function objects(value: unknown): DataObject[] {
  return Array.isArray(value) ? value.filter(isObject) : [];
}

function titleCase(value: string): string {
  return value
    .replace(/_/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function compact(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return String(value);
}

function Metric({ label, value, tone = "default" }: { label: string; value: string | number; tone?: "default" | "signal" | "quiet" }) {
  return (
    <div className="border border-[#d0ccc7] bg-white p-3">
      <p className="vv-label">{label}</p>
      <p className={`mt-1.5 break-words text-sm font-black ${tone === "signal" ? "text-[#a61b0d]" : tone === "quiet" ? "text-[#676360]" : "text-[#171616]"}`}>
        {value}
      </p>
    </div>
  );
}

function CommandInjectionProof({ content }: { content: DataObject }) {
  const timings = [
    { label: "Baseline", value: Number(content.baseline_ms ?? 0), signal: false },
    { label: "Marker probe", value: Number(content.marker_probe_ms ?? 0), signal: false },
    { label: "Blind delay", value: Number(content.blind_probe_ms ?? 0), signal: true },
  ];
  const max = Math.max(1, ...timings.map(({ value }) => value));

  return (
    <div className="space-y-4">
      <div className="grid gap-2 sm:grid-cols-3">
        <Metric label="Marker reflected" value={content.marker_reflected ? "Confirmed" : "Not reflected"} tone={content.marker_reflected ? "signal" : "quiet"} />
        <Metric label="Time delta" value={`${Math.round(Number(content.time_delta_ms ?? 0))} ms`} tone="signal" />
        <Metric label="Threshold" value={`${Math.round(Number(content.time_threshold_ms ?? 0))} ms`} />
      </div>
      <div className="border border-[#d0ccc7] bg-white p-3">
        <p className="vv-label">Probe timing comparison</p>
        <div className="mt-3 space-y-2.5">
          {timings.map((timing) => (
            <div key={timing.label} className="grid grid-cols-[82px_minmax(0,1fr)_58px] items-center gap-2">
              <span className="text-[10px] font-bold text-[#514e4b]">{timing.label}</span>
              <div className="h-2.5 bg-[#e6e3e0]">
                <div className={`h-full ${timing.signal ? "bg-[#f0321d]" : "bg-[#2b2928]"}`} style={{ width: `${(timing.value / max) * 100}%` }} />
              </div>
              <span className="text-right font-mono text-[10px]">{Math.round(timing.value)} ms</span>
            </div>
          ))}
        </div>
      </div>
      {content.output_snippet ? (
        <div>
          <p className="vv-label">Captured response output</p>
          <pre className="vv-scrollbar mt-2 max-h-44 overflow-auto border border-[#2b2928] bg-[#201f1e] p-3 font-mono text-[10px] leading-relaxed whitespace-pre-wrap break-all text-[#f3f0ed]">
            {String(content.output_snippet)}
          </pre>
        </div>
      ) : null}
      {content.auth ? <p className="text-[10px] text-[#676360]"><span className="font-black uppercase">Probe context:</span> {String(content.auth)}</p> : null}
    </div>
  );
}

function TlsProof({ content }: { content: DataObject }) {
  const protocols = isObject(content.accepted_protocols) ? Object.entries(content.accepted_protocols) : [];
  const certificate = isObject(content.certificate) ? content.certificate : {};
  const vulnerabilities = isObject(content.vulnerabilities) ? content.vulnerabilities : {};
  const deprecated = new Set(["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]);
  const issueFlags = Object.entries(vulnerabilities).filter(([key, value]) =>
    key === "supports_secure_renegotiation" ? value === false : value === true,
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        {protocols.map(([protocol, ciphers]) => {
          const count = Array.isArray(ciphers) ? ciphers.length : 0;
          const risky = deprecated.has(protocol) && count > 0;
          return (
            <div key={protocol} className={`min-w-[92px] border px-3 py-2 ${risky ? "border-[#f0321d] bg-[#fff0ed]" : "border-[#d0ccc7] bg-white"}`}>
              <p className={`text-[10px] font-black ${risky ? "text-[#b91f10]" : "text-[#171616]"}`}>{protocol}</p>
              <p className="mt-1 text-[9px] text-[#676360]">{count} accepted cipher{count === 1 ? "" : "s"}</p>
            </div>
          );
        })}
      </div>
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
        <Metric label="Certificate" value={compact(certificate.subject)} />
        <Metric
          label="Trust"
          value={certificate.is_trusted === true ? "Trusted" : certificate.is_trusted === false ? "Untrusted" : "Unknown"}
          tone={certificate.is_trusted === false ? "signal" : certificate.is_trusted === true ? "default" : "quiet"}
        />
        <Metric label="Key" value={`${compact(certificate.key_type)} ${compact(certificate.key_bits)} bit`} />
        <Metric
          label="Expiry"
          value={certificate.is_expired === true ? "Expired" : certificate.is_expired === false ? "Valid" : "Unknown"}
          tone={certificate.is_expired === true ? "signal" : certificate.is_expired === false ? "default" : "quiet"}
        />
        <Metric
          label="SHA-1 signature"
          value={certificate.signed_with_sha1 === true ? "Detected" : certificate.signed_with_sha1 === false ? "Not detected" : "Unknown"}
          tone={certificate.signed_with_sha1 === true ? "signal" : certificate.signed_with_sha1 === false ? "default" : "quiet"}
        />
        <Metric label="TLS issue flags" value={issueFlags.length} tone={issueFlags.length ? "signal" : "default"} />
      </div>
      <div className="border border-[#d0ccc7] bg-white p-3">
        <p className="vv-label">Named vulnerability checks</p>
        <div className="mt-3 flex flex-wrap gap-2">
          {Object.entries(vulnerabilities).map(([key, value]) => {
            const known = typeof value === "boolean";
            const isIssue = known && (key === "supports_secure_renegotiation" ? value === false : value === true);
            return (
              <span key={key} className={`px-2 py-1 text-[9px] font-bold uppercase tracking-wide ${isIssue ? "bg-[#ffd8d2] text-[#a61b0d]" : "bg-[#ece9e6] text-[#514e4b]"}`}>
                {titleCase(key)} · {known ? (isIssue ? "issue" : "clear") : "unknown"}
              </span>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function SensitiveFilesProof({ content }: { content: DataObject }) {
  const exposed = objects(content.exposed_files);
  const checked = Array.isArray(content.checked_paths) ? content.checked_paths : [];
  return (
    <div className="space-y-4">
      <div className="grid gap-2 sm:grid-cols-3">
        <Metric label="Exposed" value={exposed.length} tone={exposed.length ? "signal" : "default"} />
        <Metric label="Paths checked" value={Number(content.checked_count ?? checked.length)} />
        <Metric label="Probe coverage" value={checked.length ? `${Math.round((exposed.length / checked.length) * 100)}% returned exposed` : "—"} />
      </div>
      <div className="vv-scrollbar overflow-x-auto border border-[#d0ccc7] bg-white">
        <table className="vv-table min-w-[520px]">
          <thead><tr><th>Path</th><th>Category</th><th>Status</th><th className="text-right">Bytes</th></tr></thead>
          <tbody>
            {exposed.map((file, index) => (
              <tr key={`${compact(file.path)}-${index}`}>
                <td className="font-mono text-[10px] font-bold">{compact(file.path)}</td>
                <td>{titleCase(compact(file.category))}</td>
                <td><span className="bg-[#ffd8d2] px-2 py-1 text-[9px] font-black text-[#a61b0d]">HTTP {compact(file.status_code)}</span></td>
                <td className="text-right font-mono text-[10px]">{compact(file.content_length)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function WeakAuthProof({ content }: { content: DataObject }) {
  const attempts = Array.isArray(content.login_attempt_statuses) ? content.login_attempt_statuses : [];
  const distribution = attempts.reduce<Record<string, number>>((counts, status) => {
    const key = String(status);
    counts[key] = (counts[key] ?? 0) + 1;
    return counts;
  }, {});
  const enumerationChecked = content.enumeration_checked === true;
  const enumerationLeaked = content.enumeration_leaked === true;
  return (
    <div className="space-y-4">
      <div className="grid gap-2 sm:grid-cols-3">
        <Metric
          label="Account enumeration"
          value={!enumerationChecked ? "Not checked" : enumerationLeaked ? "Confirmed" : "Not confirmed"}
          tone={enumerationLeaked ? "signal" : "quiet"}
        />
        <Metric label="Login attempts" value={attempts.length} />
        <Metric label="Unique responses" value={Object.keys(distribution).length} />
      </div>
      <div className="border border-[#d0ccc7] bg-white p-3">
        <p className="vv-label">Login response sequence</p>
        <div className="mt-3 flex flex-wrap gap-1">
          {attempts.map((status, index) => (
            <span key={index} className="min-w-10 bg-[#ece9e6] px-2 py-1 text-center font-mono text-[9px] font-bold">{String(status)}</span>
          ))}
        </div>
      </div>
      <dl className="grid gap-2 text-[10px] sm:grid-cols-2">
        <div>
          <dt className="vv-label">Enumeration endpoint</dt>
          <dd className="mt-1 break-all font-mono">
            {enumerationChecked ? compact(content.enumeration_endpoint) : "Skipped — no known username supplied"}
          </dd>
        </div>
        <div><dt className="vv-label">Login endpoint</dt><dd className="mt-1 break-all font-mono">{compact(content.login_endpoint)}</dd></div>
      </dl>
    </div>
  );
}

function ServiceProof({ content }: { content: DataObject }) {
  const ports = objects(content.open_ports);
  const vulnerabilities = objects(content.vulnerabilities);
  const severityCounts = vulnerabilities.reduce<Record<string, number>>((counts, vulnerability) => {
    const key = compact(vulnerability.severity).toUpperCase();
    counts[key] = (counts[key] ?? 0) + 1;
    return counts;
  }, {});
  const exploitCount = vulnerabilities.filter((vulnerability) => vulnerability.exploit_available === true).length;

  return (
    <div className="space-y-4">
      <div className="grid gap-2 sm:grid-cols-3">
        <Metric label="Open ports" value={ports.length} tone={ports.length ? "signal" : "default"} />
        <Metric label="Matched risks" value={vulnerabilities.length} tone={vulnerabilities.length ? "signal" : "default"} />
        <Metric label="Exploit references" value={exploitCount} />
      </div>
      {vulnerabilities.length > 0 && (
        <div className="border border-[#d0ccc7] bg-white p-3">
          <p className="vv-label">Matched-risk severity</p>
          <div className="mt-3 flex h-3 overflow-hidden bg-[#e6e3e0]">
            {Object.entries(severityCounts).map(([severity, count]) => (
              <div
                key={severity}
                title={`${severity}: ${count}`}
                className={severity === "CRITICAL" ? "bg-[#b71f0e]" : severity === "HIGH" ? "bg-[#f0321d]" : severity === "MEDIUM" ? "bg-[#ff8c7c]" : "bg-[#aaa6a1]"}
                style={{ width: `${(count / vulnerabilities.length) * 100}%` }}
              />
            ))}
          </div>
          <div className="mt-2 flex flex-wrap gap-3 text-[9px] uppercase text-[#676360]">
            {Object.entries(severityCounts).map(([severity, count]) => <span key={severity}><strong className="text-[#171616]">{count}</strong> {severity}</span>)}
          </div>
        </div>
      )}
      <div className="vv-scrollbar overflow-x-auto border border-[#d0ccc7] bg-white">
        <table className="vv-table min-w-[600px]">
          <thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr></thead>
          <tbody>
            {ports.slice(0, 10).map((port, index) => (
              <tr key={`${compact(port.port)}-${index}`}>
                <td className="font-mono font-black">{compact(port.port)}/{compact(port.protocol)}</td>
                <td>{compact(port.service)}</td>
                <td>{compact(port.product)}</td>
                <td className="font-mono text-[10px]">{compact(port.version)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {ports.length > 10 && <p className="text-[10px] text-[#676360]">Showing 10 of {ports.length} ports. The complete inventory is available in raw evidence.</p>}
      {vulnerabilities.length > 0 && (
        <div>
          <p className="vv-label">Top matched vulnerabilities</p>
          <div className="mt-2 grid gap-px bg-[#d0ccc7] border border-[#d0ccc7] sm:grid-cols-2">
            {vulnerabilities.slice(0, 6).map((vulnerability, index) => (
              <div key={`${compact(vulnerability.cve)}-${index}`} className="bg-white p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[10px] font-black">{compact(vulnerability.cve)}</span>
                  <span className="bg-[#ffd8d2] px-1.5 py-0.5 text-[8px] font-black text-[#a61b0d]">{compact(vulnerability.severity)}</span>
                </div>
                <p className="mt-1 line-clamp-2 text-[10px] leading-relaxed text-[#676360]">{compact(vulnerability.description)}</p>
              </div>
            ))}
          </div>
          {vulnerabilities.length > 6 && <p className="mt-2 text-[10px] text-[#676360]">Showing 6 of {vulnerabilities.length} matches.</p>}
        </div>
      )}
    </div>
  );
}

function Primitive({ value }: { value: unknown }) {
  if (value === null || value === undefined) return <span className="text-[#918d88]">—</span>;
  if (typeof value === "boolean") {
    return <span className="bg-[#ece9e6] px-1.5 py-0.5 text-[10px] font-bold text-[#514e4b]">{value ? "true" : "false"}</span>;
  }
  if (typeof value === "number") return <span className="font-mono text-[10px]">{value}</span>;
  const text = String(value);
  if (text.length > 100 || text.includes("\n")) {
    return <pre className="vv-scrollbar mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-all bg-[#eeece9] p-2 font-mono text-[10px] leading-relaxed">{text}</pre>;
  }
  return <span className="break-all font-mono text-[10px]">{text}</span>;
}

function RawNode({ value, depth = 0 }: { value: unknown; depth?: number }) {
  const [showAll, setShowAll] = useState(false);
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="text-[10px] text-[#918d88]">Empty list</span>;
    const visible = showAll ? value : value.slice(0, 8);
    return (
      <div className="space-y-1.5">
        {visible.map((item, index) => (
          <div key={index} className="border-l border-[#d0ccc7] pl-2">
            <span className="mr-2 text-[9px] font-black text-[#918d88]">{String(index + 1).padStart(2, "0")}</span>
            <RawNode value={item} depth={depth + 1} />
          </div>
        ))}
        {value.length > 8 && (
          <button type="button" onClick={() => setShowAll((current) => !current)} className="text-[9px] font-black uppercase tracking-wide text-[#a61b0d] hover:underline">
            {showAll ? "Show less" : `Show ${value.length - 8} more`}
          </button>
        )}
      </div>
    );
  }
  if (isObject(value)) {
    return (
      <dl className="space-y-2">
        {Object.entries(value).map(([key, child]) => {
          const nested = isObject(child) || Array.isArray(child);
          return (
            <div key={key} className={nested ? "" : "grid grid-cols-[minmax(92px,0.3fr)_minmax(0,1fr)] gap-3"}>
              <dt className="text-[9px] font-black uppercase tracking-[0.07em] text-[#676360]">{titleCase(key)}</dt>
              <dd className={nested ? "mt-1 pl-2" : "min-w-0"}><RawNode value={child} depth={depth + 1} /></dd>
            </div>
          );
        })}
      </dl>
    );
  }
  return <Primitive value={value} />;
}

export default function EvidenceViewer({ content, detectorId }: { content: DataObject; detectorId?: string }) {
  const [showRaw, setShowRaw] = useState(false);
  const [copied, setCopied] = useState(false);

  async function copyEvidence() {
    try {
      await navigator.clipboard.writeText(JSON.stringify(content, null, 2));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  }

  let summary: React.ReactNode;
  if (detectorId === "command_injection") summary = <CommandInjectionProof content={content} />;
  else if (detectorId === "weak_tls") summary = <TlsProof content={content} />;
  else if (detectorId === "sensitive_files") summary = <SensitiveFilesProof content={content} />;
  else if (detectorId === "weak_auth") summary = <WeakAuthProof content={content} />;
  else if (detectorId === "vulnerable_services") summary = <ServiceProof content={content} />;
  else summary = <p className="text-xs text-[#676360]">Structured detector evidence is available below.</p>;

  return (
    <div className="border border-[#aaa6a1] bg-[#f7f6f4] p-4">
      {summary}
      <div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t border-[#d0ccc7] pt-3">
        <button type="button" onClick={() => setShowRaw((current) => !current)} className="text-[9px] font-black uppercase tracking-[0.08em] text-[#a61b0d] hover:underline" aria-expanded={showRaw}>
          {showRaw ? "Hide raw evidence" : "Inspect raw evidence"}
        </button>
        <button type="button" onClick={copyEvidence} className="text-[9px] font-black uppercase tracking-[0.08em] text-[#514e4b] hover:text-[#a61b0d]">
          {copied ? "Copied" : "Copy JSON"}
        </button>
      </div>
      {showRaw && (
        <div className="vv-scrollbar mt-3 max-h-[520px] overflow-auto border border-[#d0ccc7] bg-white p-3">
          <RawNode value={content} />
        </div>
      )}
    </div>
  );
}
