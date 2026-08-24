import { useState } from "react";
import type { FormEvent } from "react";
import { Link } from "react-router-dom";
import AuthShell, { AuthLink } from "../components/AuthShell";
import { api } from "../services/api";

export default function ForgotPassword() {
  const [identity, setIdentity] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitted, setSubmitted] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.requestPasswordReset(identity);
      setSubmitted(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not request a reset");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell
      eyebrow="Account recovery"
      title="Forgot password"
      description="Request a single-use reset token for your account. It stays valid for a short window and can only be redeemed once."
      footer={
        <>
          <AuthLink to="/login">Back to sign in</AuthLink>
          <AuthLink to="/reset-password">I already have a token</AuthLink>
        </>
      }
    >
      {submitted ? (
        <div className="space-y-4">
          <p role="status" className="vv-alert vv-alert-success">
            If that account exists, a reset token has been issued.
          </p>
          <p className="vv-hint">
            VulnVista has no mail transport in the lab deployment, so the token is written to the
            backend log for an administrator to relay. Ask an administrator for it, then redeem it
            below.
          </p>
          <Link to="/reset-password" className="vv-button-primary w-full">
            Enter reset token
          </Link>
        </div>
      ) : (
        <form onSubmit={submit} className="space-y-5">
          <label className="vv-field">
            <span className="vv-label">Username or email</span>
            <input
              autoFocus
              required
              disabled={busy}
              autoComplete="username"
              value={identity}
              onChange={(event) => setIdentity(event.target.value)}
              className="vv-input"
            />
            <span className="vv-hint">
              The response is the same whether or not the account exists.
            </span>
          </label>

          {error && (
            <p role="alert" className="vv-alert vv-alert-danger">
              {error}
            </p>
          )}

          <button type="submit" disabled={busy} className="vv-button-primary w-full">
            {busy ? "Requesting…" : "Request reset token"}
          </button>
        </form>
      )}
    </AuthShell>
  );
}
