import { NavLink, Outlet } from "react-router-dom";
import { useHealth } from "../hooks/useHealth";
import { useAuth } from "../auth/useAuth";

const navItems = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/targets", label: "Targets" },
  { to: "/scans", label: "Scans" },
  { to: "/findings", label: "Findings" },
];

export default function Layout() {
  const health = useHealth();
  const { user, logout } = useAuth();

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
            {user?.role === "ADMIN" && (
              <NavLink
                to="/users"
                className={({ isActive }) =>
                  isActive ? "text-white" : "text-slate-400 hover:text-slate-200"
                }
              >
                Users
              </NavLink>
            )}
          </nav>
          <div className="flex items-center gap-4 text-xs text-slate-400">
            <span className="flex items-center gap-2"><span
              className={`h-2 w-2 rounded-full ${
                health === "online"
                  ? "bg-emerald-500"
                  : health === "offline"
                    ? "bg-red-500"
                    : "bg-amber-500"
              }`}
            /> API {health}</span>
            <span>{user?.username} · {user?.role}</span>
            <button type="button" onClick={() => void logout()} className="text-slate-300 hover:text-white">Sign out</button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-6 py-8">
        <Outlet />
      </main>
    </div>
  );
}
