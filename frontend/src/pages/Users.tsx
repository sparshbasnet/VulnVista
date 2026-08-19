import { useState } from "react";
import type { FormEvent } from "react";
import { api } from "../services/api";
import type { User, UserRole } from "../types";

const roles: Array<{ value: UserRole; label: string; description: string }> = [
  {
    value: "VIEWER",
    label: "Viewer",
    description: "Read-only access to targets, scans, and findings.",
  },
  {
    value: "ANALYST",
    label: "Analyst",
    description: "Can register targets, run scans, and update finding status.",
  },
  {
    value: "ADMIN",
    label: "Administrator",
    description: "Full analyst access plus permission to create platform users.",
  },
];

export default function Users() {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [role, setRole] = useState<UserRole>("VIEWER");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<User | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setCreated(null);
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setBusy(true);
    try {
      const user = await api.createUser({ username, email, password, role });
      setCreated(user);
      setUsername("");
      setEmail("");
      setPassword("");
      setConfirmPassword("");
      setRole("VIEWER");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create user");
    } finally {
      setBusy(false);
    }
  }

  const selectedRole = roles.find((item) => item.value === role);

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">User management</h1>
        <p className="mt-1 text-sm text-slate-400">
          Create an operator account and choose the minimum access it needs.
        </p>
      </div>

      <form
        onSubmit={submit}
        className="space-y-5 rounded-lg border border-slate-800 bg-slate-900/40 p-6"
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="text-sm text-slate-300">
            Username
            <input
              autoFocus
              required
              minLength={3}
              maxLength={64}
              pattern="[A-Za-z0-9_.-]+"
              autoComplete="off"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              className="mt-1.5 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 outline-none focus:border-sky-500"
              placeholder="jane.smith"
            />
          </label>
          <label className="text-sm text-slate-300">
            Email
            <input
              type="email"
              required
              maxLength={255}
              autoComplete="off"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              className="mt-1.5 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 outline-none focus:border-sky-500"
              placeholder="jane@example.test"
            />
          </label>
          <label className="text-sm text-slate-300">
            Temporary password
            <input
              type="password"
              required
              minLength={12}
              maxLength={72}
              autoComplete="new-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="mt-1.5 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 outline-none focus:border-sky-500"
            />
            <span className="mt-1 block text-xs text-slate-500">12–72 characters.</span>
          </label>
          <label className="text-sm text-slate-300">
            Confirm password
            <input
              type="password"
              required
              minLength={12}
              maxLength={72}
              autoComplete="new-password"
              value={confirmPassword}
              onChange={(event) => setConfirmPassword(event.target.value)}
              className="mt-1.5 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 outline-none focus:border-sky-500"
            />
          </label>
        </div>

        <label className="block text-sm text-slate-300">
          Role
          <select
            value={role}
            onChange={(event) => setRole(event.target.value as UserRole)}
            className="mt-1.5 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 outline-none focus:border-sky-500"
          >
            {roles.map((item) => (
              <option key={item.value} value={item.value}>
                {item.label}
              </option>
            ))}
          </select>
          <span className="mt-1.5 block text-xs text-slate-500">
            {selectedRole?.description}
          </span>
        </label>

        {error && (
          <p role="alert" className="rounded-md border border-red-900/60 bg-red-950/40 p-3 text-sm text-red-300">
            {error}
          </p>
        )}
        {created && (
          <p role="status" className="rounded-md border border-emerald-900/60 bg-emerald-950/40 p-3 text-sm text-emerald-300">
            Created {created.username} with the {created.role.toLowerCase()} role.
          </p>
        )}

        <div className="flex justify-end">
          <button
            type="submit"
            disabled={busy}
            className="rounded-md bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? "Creating…" : "Create user"}
          </button>
        </div>
      </form>

      <p className="text-xs text-slate-500">
        Password changes, recovery, role editing, and account deactivation are not available yet.
      </p>
    </div>
  );
}
