import { useId } from "react";
import { PASSWORD_POLICY_HINT, describePasswordProblem, passwordStrength } from "../lib/password";

const STRENGTH_LABELS = ["", "Weak", "Fair", "Good", "Strong"];
const STRENGTH_COLORS = ["#dedbd7", "#d62d18", "#e2820f", "#7d9a2e", "#167249"];

/**
 * The "choose a new password" pair used by account settings, recovery, and user
 * creation, so the rules and the feedback are worded identically everywhere.
 */
export default function NewPasswordFields({
  password,
  confirmPassword,
  onPasswordChange,
  onConfirmChange,
  label = "New password",
  confirmLabel,
  disabled = false,
  autoFocus = false,
}: {
  password: string;
  confirmPassword: string;
  onPasswordChange: (value: string) => void;
  onConfirmChange: (value: string) => void;
  label?: string;
  confirmLabel?: string;
  disabled?: boolean;
  autoFocus?: boolean;
}) {
  const policyId = useId();
  const problem = password ? describePasswordProblem(password) : null;
  const mismatch = confirmPassword.length > 0 && password !== confirmPassword;
  const strength = passwordStrength(password);

  return (
    <>
      <label className="vv-field">
        <span className="vv-label">{label}</span>
        <input
          type="password"
          required
          autoFocus={autoFocus}
          disabled={disabled}
          autoComplete="new-password"
          value={password}
          onChange={(event) => onPasswordChange(event.target.value)}
          aria-describedby={policyId}
          className="vv-input"
        />
        <span className="mt-2 flex items-center gap-2" aria-hidden="true">
          <span className="flex h-1 flex-1 gap-1">
            {[1, 2, 3, 4].map((step) => (
              <span
                key={step}
                className="flex-1"
                style={{ background: step <= strength ? STRENGTH_COLORS[strength] : "#dedbd7" }}
              />
            ))}
          </span>
          <span className="w-12 text-right text-[9px] font-black uppercase tracking-wider text-[#676360]">
            {STRENGTH_LABELS[strength]}
          </span>
        </span>
        <span id={policyId} className="vv-hint">
          {problem ?? PASSWORD_POLICY_HINT}
        </span>
      </label>

      <label className="vv-field">
        <span className="vv-label">{confirmLabel ?? `Confirm ${label.toLowerCase()}`}</span>
        <input
          type="password"
          required
          disabled={disabled}
          autoComplete="new-password"
          value={confirmPassword}
          onChange={(event) => onConfirmChange(event.target.value)}
          className="vv-input"
        />
        {mismatch && <span className="vv-hint text-[#a61b0d]">Passwords do not match.</span>}
      </label>
    </>
  );
}
