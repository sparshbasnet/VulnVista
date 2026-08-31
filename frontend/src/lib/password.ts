/**
 * Client-side mirror of the backend password policy
 * (`backend/app/core/security.py::validate_password_policy`).
 *
 * This exists to fail fast in the form; the server re-checks every rule and
 * stays the authority. Keep the two in step.
 */

export const MIN_PASSWORD_LENGTH = 12;
export const MAX_PASSWORD_BYTES = 72;
export const REQUIRED_CHARACTER_CLASSES = 3;

export const PASSWORD_POLICY_HINT =
  `At least ${MIN_PASSWORD_LENGTH} characters, combining ${REQUIRED_CHARACTER_CLASSES} of: ` +
  "lowercase, uppercase, digits, symbols.";

function byteLength(value: string): number {
  return new TextEncoder().encode(value).length;
}

export function countCharacterClasses(password: string): number {
  return [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((pattern) => pattern.test(password))
    .length;
}

/** Returns the first unmet rule, or null when the password is acceptable. */
export function describePasswordProblem(password: string): string | null {
  if (password.length < MIN_PASSWORD_LENGTH) {
    return `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`;
  }
  if (byteLength(password) > MAX_PASSWORD_BYTES) {
    return `Password must be at most ${MAX_PASSWORD_BYTES} bytes.`;
  }
  if (countCharacterClasses(password) < REQUIRED_CHARACTER_CLASSES) {
    return "Password must combine at least three of: lowercase, uppercase, digits, symbols.";
  }
  return null;
}

/** 0–4, for the strength meter. Length past the minimum counts as one step. */
export function passwordStrength(password: string): number {
  if (!password) return 0;
  const classes = countCharacterClasses(password);
  const lengthBonus = password.length >= MIN_PASSWORD_LENGTH + 4 ? 1 : 0;
  return Math.min(4, Math.max(1, classes - 1 + lengthBonus));
}
