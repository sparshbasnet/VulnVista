import { Link, NavLink, Outlet } from "react-router-dom";
import { useHealth } from "../hooks/useHealth";
import { useAuth } from "../auth/useAuth";
import { useAppData } from "../hooks/useAppData";
import { downloadFindingsReport } from "../lib/report";

const navBase =
  "group flex min-h-10 items-center justify-between gap-3 px-3 text-[11px] font-extrabold uppercase tracking-[0.08em] transition-colors";

export default function Layout() {
  const health = useHealth();
  const { user, logout } = useAuth();
  const { targets, scans, findings } = useAppData();
  const evidenceCount = findings.reduce((total, finding) => total + (finding.evidence?.length ?? 0), 0);

  const navItems = [
    { to: "/", label: "Dashboard", end: true, count: null },
    { to: "/scans", label: "Scans", end: false, count: scans.length },
    { to: "/findings", label: "Findings", end: false, count: findings.length },
    { to: "/targets", label: "Targets", end: false, count: targets.length },
    { to: "/evidence", label: "Evidence", end: false, count: evidenceCount },
    ...(user?.role === "ADMIN" ? [{ to: "/users", label: "Users", end: false, count: null }] : []),
    { to: "/account", label: "Account", end: false, count: null },
  ];

  const apiTone =
    health === "online" ? "bg-emerald-500" : health === "offline" ? "bg-red-600" : "bg-amber-500";

  return (
    <div className="min-h-screen bg-[#e9e7e4] text-[#171616] lg:grid lg:grid-cols-[232px_minmax(0,1fr)]">
      <a
        href="#app-content"
        className="fixed top-2 left-2 z-[100] -translate-y-20 bg-[#171616] px-4 py-2 text-xs font-black uppercase tracking-wide text-white focus:translate-y-0"
      >
        Skip to content
      </a>
      <aside className="relative hidden h-screen flex-col border-r border-[#8f8b87] bg-[#f7f6f4] lg:sticky lg:top-0 lg:flex">
        <div className="absolute inset-y-0 left-0 w-1 bg-[#f0321d]" aria-hidden="true" />

        <div className="border-b border-[#8f8b87] px-5 py-6">
          <span className="text-[19px] font-black tracking-[-0.04em]">
            VULN<span className="text-[#f0321d]">VISTA</span>
          </span>
          <p className="mt-1 text-[9px] font-semibold uppercase tracking-[0.18em] text-[#676360]">
            15-detector scanner
          </p>
        </div>

        <nav className="flex-1 px-3 py-3" aria-label="Primary navigation">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `${navBase} ${
                  isActive
                    ? "bg-[#d62d18] text-white"
                    : "text-[#171616] hover:bg-white"
                }`
              }
            >
              {({ isActive }) => (
                <>
                  <span className="flex items-center gap-3">
                    <span
                      className={`h-px w-5 ${isActive ? "bg-white" : "bg-[#77736f] group-hover:bg-[#f0321d]"}`}
                      aria-hidden="true"
                    />
                    {item.label}
                  </span>
                  {item.count !== null && (
                    <span className={isActive ? "text-white" : "text-[#85817d]"}>{item.count}</span>
                  )}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-[#8f8b87] p-4">
          <button
            type="button"
            onClick={() => downloadFindingsReport(findings)}
            disabled={findings.length === 0}
            className="vv-button-primary w-full"
          >
            Generate report
          </button>
          <p className="mt-3 text-[10px] leading-relaxed text-[#676360]">
            Lab scope only · authorization enforced per target
          </p>
          <p className="mt-3 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wider text-[#676360]">
            <span className={`h-2 w-2 ${apiTone}`} aria-hidden="true" />
            API {health}
          </p>
          <div className="mt-3 flex items-center justify-between gap-2 border-t border-[#d8d4cf] pt-3 text-[10px] font-semibold uppercase tracking-wider text-[#676360]">
            <Link to="/account" className="min-w-0 truncate hover:text-[#171616] hover:underline">
              {user?.username} · {user?.role}
            </Link>
            <button type="button" onClick={() => void logout()} className="shrink-0 text-[#a61b0d] hover:underline">
              Sign out
            </button>
          </div>
        </div>
      </aside>

      <div className="min-w-0">
        <header className="sticky top-0 z-40 border-b border-[#8f8b87] bg-[#f7f6f4] lg:hidden">
          <div className="flex h-14 items-center justify-between gap-3 px-4">
            <span className="text-[17px] font-black tracking-[-0.04em]">
              VULN<span className="text-[#f0321d]">VISTA</span>
            </span>
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1.5 text-[9px] font-bold uppercase tracking-wider text-[#676360]">
                <span className={`h-2 w-2 ${apiTone}`} aria-hidden="true" />
                {health}
              </span>
              <button
                type="button"
                onClick={() => downloadFindingsReport(findings)}
                disabled={findings.length === 0}
                className="vv-button-primary min-h-8 px-2.5 text-[10px]"
              >
                Report
              </button>
            </div>
          </div>
          <nav className="vv-scrollbar flex max-w-full overflow-x-auto border-t border-[#d8d4cf] px-2" aria-label="Primary navigation">
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  `shrink-0 border-b-2 px-3 py-2.5 text-[10px] font-extrabold uppercase tracking-[0.08em] ${
                    isActive
                      ? "border-[#d62d18] text-[#a61b0d]"
                      : "border-transparent text-[#676360]"
                  }`
                }
              >
                {item.label}
                {item.count !== null && <span className="ml-1.5 text-[9px]">{item.count}</span>}
              </NavLink>
            ))}
          </nav>
        </header>

        <main id="app-content" tabIndex={-1} className="min-w-0 bg-[#f7f6f4]">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
