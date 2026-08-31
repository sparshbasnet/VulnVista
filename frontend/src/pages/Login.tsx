import { useState } from "react";
import type { FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import AuthShell, { AuthLink } from "../components/AuthShell";
import { useAuth } from "../auth/useAuth";

export default function Login() {
  const { user, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (user) return <Navigate to="/" replace />;

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username, password);
      const from = (location.state as { from?: { pathname?: string } } | null)?.from?.pathname;
      navigate(from ?? "/", { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell
      eyebrow="Operator access"
      title="Sign in"
      description="Use the platform account issued to you. Repeated failed attempts lock the account temporarily."
      footer={
        <>
          <AuthLink to="/forgot-password">Forgot your password?</AuthLink>
          <span>Have a reset token? <AuthLink to="/reset-password">Redeem it</AuthLink></span>
        </>
      }
    >
      <form onSubmit={submit} className="space-y-5">
        <label className="vv-field">
          <span className="vv-label">Username or email</span>
          <input
            autoFocus
            autoComplete="username"
            required
            disabled={busy}
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            className="vv-input"
          />
        </label>

        <label className="vv-field">
          <span className="vv-label">Password</span>
          <input
            type="password"
            autoComplete="current-password"
            required
            disabled={busy}
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            className="vv-input"
          />
        </label>

        {error && (
          <p role="alert" className="vv-alert vv-alert-danger">
            {error}
          </p>
        )}

        <button type="submit" disabled={busy} className="vv-button-primary w-full">
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </AuthShell>
  );
}
