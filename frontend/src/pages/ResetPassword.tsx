import { useState } from "react";
import type { FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import AuthShell, { AuthLink } from "../components/AuthShell";
import NewPasswordFields from "../components/NewPasswordFields";
import { describePasswordProblem } from "../lib/password";
import { api } from "../services/api";

export default function ResetPassword() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  // A token can arrive in the link an administrator relays, or be pasted by hand.
  const [token, setToken] = useState(searchParams.get("token") ?? "");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);

    const problem = describePasswordProblem(password);
    if (problem) return setError(problem);
    if (password !== confirmPassword) return setError("Passwords do not match.");

    setBusy(true);
    try {
      await api.confirmPasswordReset(token.trim(), password);
      setDone(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not reset the password");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell
      eyebrow="Account recovery"
      title="Set a new password"
      description="Redeem the single-use token issued for your account. Redeeming it also signs out every session that account had open."
      footer={
        <>
          <AuthLink to="/login">Back to sign in</AuthLink>
          <AuthLink to="/forgot-password">Request a new token</AuthLink>
        </>
      }
    >
      {done ? (
        <div className="space-y-4">
          <p role="status" className="vv-alert vv-alert-success">
            Password updated. Sign in with your new password.
          </p>
          <Link to="/login" className="vv-button-primary w-full">
            Go to sign in
          </Link>
        </div>
      ) : (
        <form onSubmit={submit} className="space-y-5">
          <label className="vv-field">
            <span className="vv-label">Reset token</span>
            <input
              required
              autoFocus={!token}
              disabled={busy}
              autoComplete="one-time-code"
              spellCheck={false}
              value={token}
              onChange={(event) => setToken(event.target.value)}
              className="vv-input font-mono text-xs"
            />
            <span className="vv-hint">Single use, and it expires shortly after being issued.</span>
          </label>

          <NewPasswordFields
            password={password}
            confirmPassword={confirmPassword}
            onPasswordChange={setPassword}
            onConfirmChange={setConfirmPassword}
            disabled={busy}
            autoFocus={Boolean(token)}
          />

          {error && (
            <p role="alert" className="vv-alert vv-alert-danger">
              {error}
            </p>
          )}

          <div className="flex gap-2">
            <button
              type="button"
              disabled={busy}
              onClick={() => navigate("/login")}
              className="vv-button-secondary flex-1"
            >
              Cancel
            </button>
            <button type="submit" disabled={busy} className="vv-button-primary flex-1">
              {busy ? "Saving…" : "Set password"}
            </button>
          </div>
        </form>
      )}
    </AuthShell>
  );
}
