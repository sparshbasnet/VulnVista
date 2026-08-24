import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "./useAuth";

const FORCED_CHANGE_PATH = "/change-password";

export default function ProtectedRoute() {
  const { user, loading, mustChangePassword } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="grid min-h-screen place-items-center bg-[#e9e7e4] text-xs font-bold uppercase tracking-[0.16em] text-[#676360]">
        Loading…
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace state={{ from: location }} />;
  // A temporary password authorizes nothing but its own replacement, so send the
  // account there rather than letting it collect 403s across the app.
  if (mustChangePassword && location.pathname !== FORCED_CHANGE_PATH) {
    return <Navigate to={FORCED_CHANGE_PATH} replace />;
  }
  return <Outlet />;
}
