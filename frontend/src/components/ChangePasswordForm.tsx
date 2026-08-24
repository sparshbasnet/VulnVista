import { useState } from "react";
import type { FormEvent } from "react";
import { useAuth } from "../auth/useAuth";
import { describePasswordProblem } from "../lib/password";
import NewPasswordFields from "./NewPasswordFields";

/**
 * Self-service password change. Used both from account settings and from the
 * forced change an administrator-issued temporary password triggers.
 */
export default function ChangePasswordForm({
  submitLabel = "Change password",
  onChanged,
}: {
  submitLabel?: string;
  onChanged?: () => void;
}) {
  const { changePassword } = useAuth();
  const [currentPassword, setCurrentPassword] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setDone(false);

    const problem = describePasswordProblem(password);
    if (problem) return setError(problem);
    if (password !== confirmPassword) return setError("Passwords do not match.");
    if (password === currentPassword) {
      return setError("New password must differ from the current password.");
    }

    setBusy(true);
    try {
      await changePassword(currentPassword, password);
      setCurrentPassword("");
      setPassword("");
      setConfirmPassword("");
      setDone(true);
      onChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not change password");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-5">
      <label className="vv-field">
        <span className="vv-label">Current password</span>
        <input
          type="password"
          required
          autoFocus
          disabled={busy}
          autoComplete="current-password"
          value={currentPassword}
          onChange={(event) => setCurrentPassword(event.target.value)}
          className="vv-input"
        />
      </label>

      <NewPasswordFields
        password={password}
        confirmPassword={confirmPassword}
        onPasswordChange={setPassword}
        onConfirmChange={setConfirmPassword}
        disabled={busy}
      />

      {error && (
        <p role="alert" className="vv-alert vv-alert-danger">
          {error}
        </p>
      )}
      {done && (
        <p role="status" className="vv-alert vv-alert-success">
          Password changed. Any other session signed in as you has been signed out.
        </p>
      )}

      <button type="submit" disabled={busy} className="vv-button-primary w-full">
        {busy ? "Saving…" : submitLabel}
      </button>

      <p className="vv-hint">
        Changing your password revokes every access token issued to this account, including sessions
        open in other browsers.
      </p>
    </form>
  );
}
