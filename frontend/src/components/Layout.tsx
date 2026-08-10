import { NavLink, Outlet } from "react-router-dom";
import { useHealth } from "../hooks/useHealth";

const navItems = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/targets", label: "Targets" },
  { to: "/scans", label: "Scans" },
  { to: "/findings", label: "Findings" },
];

export default function Layout() {
  const health = useHealth();

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <span className="text-lg font-semibold tracking-tight">VulnVista</span>
          <nav className="flex gap-4 text-sm">
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  isActive ? "text-white" : "text-slate-400 hover:text-slate-200"
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
          <span className="flex items-center gap-2 text-xs text-slate-400">
            <span
              className={`h-2 w-2 rounded-full ${
                health === "online"
                  ? "bg-emerald-500"
                  : health === "offline"
                    ? "bg-red-500"
                    : "bg-amber-500"
              }`}
            />
            API {health}
          </span>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-6 py-8">
        <Outlet />
      </main>
    </div>
  );
}
