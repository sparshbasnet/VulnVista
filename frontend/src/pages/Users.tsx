import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import PageHeader from "../components/PageHeader";
import NewPasswordFields from "../components/NewPasswordFields";
import { useAuth } from "../auth/useAuth";
import { describePasswordProblem } from "../lib/password";
import { api } from "../services/api";
import type { PasswordResetIssued, User, UserRole } from "../types";

const ROLES: Array<{ value: UserRole; label: string; description: string }> = [
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
    description: "Full analyst access plus permission to administer platform users.",
  },
];

function formatDateTime(value: string | null | undefined): string {
  if (!value) return "—";
  return new Intl.DateTimeFormat(undefined, {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

function isLockedOut(user: User): boolean {
  return user.locked_until !== null && new Date(user.locked_until) > new Date();
}

function Stat({ label, value, signal = false }: { label: string; value: number; signal?: boolean }) {
  return (
    <div className="bg-[#f7f6f4] p-4">
      <p className="vv-label">{label}</p>
      <p
        className={`mt-1 text-2xl font-black tracking-[-0.04em] ${
          signal ? "text-[#a61b0d]" : "text-[#171616]"
        }`}
      >
        {value}
      </p>
    </div>
  );
}

function AccountState({ user }: { user: User }) {
  if (!user.is_active) {
    return <span className="vv-badge bg-[#d5d1cd] text-[#393634]">Deactivated</span>;
  }
  if (isLockedOut(user)) {
    return <span className="vv-badge bg-[#ffb2a8] text-[#76180e]">Locked out</span>;
  }
  if (user.must_change_password) {
    return <span className="vv-badge bg-[#ffd8d2] text-[#a61b0d]">Temp password</span>;
  }
  return <span className="vv-badge bg-[#e5f3eb] text-[#167249]">Active</span>;
}

export default function Users() {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [listError, setListError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [issued, setIssued] = useState<PasswordResetIssued | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setUsers(await api.listUsers());
      setListError(null);
    } catch (err) {
      setListError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const activeAdmins = useMemo(
    () => users.filter((user) => user.role === "ADMIN" && user.is_active).length,
    [users],
  );

  function applyUpdate(updated: User) {
    setUsers((current) => current.map((user) => (user.id === updated.id ? updated : user)));
  }

  async function runAction(id: string, action: () => Promise<void>) {
    setBusyId(id);
    setActionError(null);
    setNotice(null);
    try {
      await action();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusyId(null);
    }
  }

  async function changeRole(user: User, role: UserRole) {
    await runAction(user.id, async () => {
      applyUpdate(await api.updateUser(user.id, { role }));
      setNotice(`${user.username} is now a ${role.toLowerCase()}.`);
    });
  }

  async function toggleActive(user: User) {
    await runAction(user.id, async () => {
      const updated = await api.updateUser(user.id, { is_active: !user.is_active });
      applyUpdate(updated);
      setNotice(
        updated.is_active
          ? `${user.username} reactivated.`
          : `${user.username} deactivated. Their open sessions were signed out.`,
      );
    });
  }

  async function issueReset(user: User) {
    await runAction(user.id, async () => {
      setIssued(await api.issuePasswordReset(user.id));
      // The reset clears any lockout, so the row is stale either way.
      await load();
    });
  }

  return (
    <div className="bg-[#f7f6f4]">
      <PageHeader
        eyebrow="Access control"
        title="Platform users"
        description="Operator accounts, the access each one holds, and the credential actions available to an administrator."
        right={
          <button
            type="button"
            onClick={() => setShowCreate((open) => !open)}
            className="vv-button-primary mx-4 self-center"
          >
            {showCreate ? "Close form" : "New user"}
          </button>
        }
      />

      {listError && (
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#b91f10] bg-[#fff1ef] px-5 py-3 text-xs text-[#8f190e]">
          <span>Users could not be loaded: {listError}</span>
          <button type="button" onClick={() => void load()} className="font-black uppercase tracking-wide hover:underline">
            Try again
          </button>
        </div>
      )}

      <section className="grid grid-cols-2 gap-px border-b border-[#aaa6a1] bg-[#aaa6a1] sm:grid-cols-4">
        <Stat label="Accounts" value={users.length} />
        <Stat label="Administrators" value={activeAdmins} />
        <Stat label="Deactivated" value={users.filter((user) => !user.is_active).length} />
        <Stat
          label="Needs attention"
          value={users.filter((user) => isLockedOut(user) || user.must_change_password).length}
          signal
        />
      </section>

      {showCreate && (
        <CreateUserPanel
          onCreated={(user) => {
            setUsers((current) => [...current, user].sort((a, b) => a.username.localeCompare(b.username)));
            setShowCreate(false);
            setNotice(`Created ${user.username}. Hand over the password out of band — they must change it at first sign-in.`);
          }}
        />
      )}

      {issued && (
        <IssuedTokenPanel issued={issued} onDismiss={() => setIssued(null)} />
      )}

      {(actionError || notice) && (
        <div className="border-b border-[#aaa6a1] px-4 py-3 sm:px-5">
          {actionError && (
            <p role="alert" className="vv-alert vv-alert-danger">
              {actionError}
            </p>
          )}
          {notice && !actionError && (
            <p role="status" className="vv-alert vv-alert-success">
              {notice}
            </p>
          )}
        </div>
      )}

      <section className="p-4 sm:p-5 lg:p-6">
        <div className="vv-scrollbar overflow-x-auto border border-[#aaa6a1]">
          <table className="vv-table min-w-[900px] bg-[#f7f6f4]">
            <thead>
              <tr>
                <th>Account</th>
                <th>State</th>
                <th>Role</th>
                <th>Last sign-in</th>
                <th>Password changed</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => {
                const isSelf = user.id === currentUser?.id;
                const rowBusy = busyId === user.id;
                return (
                  <tr key={user.id}>
                    <td>
                      <p className="font-black">
                        {user.username}
                        {isSelf && (
                          <span className="ml-2 text-[9px] font-bold uppercase tracking-wider text-[#85817d]">
                            you
                          </span>
                        )}
                      </p>
                      <p className="mt-1 max-w-[240px] truncate text-[10px] text-[#676360]" title={user.email}>
                        {user.email}
                      </p>
                    </td>
                    <td>
                      <AccountState user={user} />
                      {isLockedOut(user) && (
                        <p className="mt-1 text-[9px] text-[#676360]">
                          until {formatDateTime(user.locked_until)}
                        </p>
                      )}
                    </td>
                    <td>
                      <select
                        value={user.role}
                        disabled={isSelf || rowBusy}
                        onChange={(event) => void changeRole(user, event.target.value as UserRole)}
                        aria-label={`Role for ${user.username}`}
                        className="vv-input min-h-8 max-w-[10rem] py-1 text-[11px]"
                      >
                        {ROLES.map((role) => (
                          <option key={role.value} value={role.value}>
                            {role.label}
                          </option>
                        ))}
                      </select>
                      {isSelf && <p className="vv-hint">Ask another administrator.</p>}
                    </td>
                    <td className="text-[10px] font-bold">{formatDateTime(user.last_login_at)}</td>
                    <td className="text-[10px] font-bold">
                      {user.password_changed_at ? formatDateTime(user.password_changed_at) : "Never"}
                    </td>
                    <td>
                      <div className="flex justify-end gap-2">
                        <button
                          type="button"
                          disabled={rowBusy || !user.is_active}
                          onClick={() => void issueReset(user)}
                          className="vv-button-secondary min-h-8 px-2.5 text-[10px]"
                        >
                          Reset password
                        </button>
                        <button
                          type="button"
                          disabled={isSelf || rowBusy}
                          onClick={() => void toggleActive(user)}
                          className="vv-button-secondary min-h-8 px-2.5 text-[10px]"
                        >
                          {user.is_active ? "Deactivate" : "Reactivate"}
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
              {loading && users.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-[#676360]">
                    Loading accounts…
                  </td>
                </tr>
              )}
              {!loading && users.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-[#676360]">
                    No accounts yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-[9px] leading-relaxed text-[#676360]">
          Deactivating an account or resetting its password revokes every access token already
          issued to it. You cannot edit your own role or deactivate yourself — that rule is also
          what keeps at least one administrator standing, so provision a second administrator
          before changing this one.
        </p>
      </section>
    </div>
  );
}

function IssuedTokenPanel({
  issued,
  onDismiss,
}: {
  issued: PasswordResetIssued;
  onDismiss: () => void;
}) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(issued.reset_token);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <section className="border-b border-[#aaa6a1] bg-[#efedea] p-4 sm:p-5">
      <div className="vv-panel vv-panel-accent p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="vv-kicker">Reset token issued</p>
            <h2 className="mt-1 text-lg font-black tracking-[-0.03em]">
              For {issued.username}
            </h2>
          </div>
          <button type="button" onClick={onDismiss} className="vv-button-secondary min-h-8 px-3 text-[10px]">
            Dismiss
          </button>
        </div>

        <p className="mt-3 text-xs leading-relaxed text-[#676360]">
          Shown once. Hand it to the account owner over a channel you trust — they redeem it at{" "}
          <span className="font-mono text-[11px]">/reset-password</span>. It is single-use and expires{" "}
          {new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
            new Date(issued.expires_at),
          )}
          .
        </p>

        <code className="vv-code mt-3">{issued.reset_token}</code>

        <div className="mt-3 flex items-center gap-3">
          <button type="button" onClick={() => void copy()} className="vv-button-primary min-h-8 px-3 text-[10px]">
            Copy token
          </button>
          {copied && (
            <span role="status" className="text-[10px] font-bold uppercase tracking-wider text-[#167249]">
              Copied
            </span>
          )}
        </div>
      </div>
    </section>
  );
}

function CreateUserPanel({ onCreated }: { onCreated: (user: User) => void }) {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [role, setRole] = useState<UserRole>("VIEWER");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);

    const problem = describePasswordProblem(password);
    if (problem) return setError(problem);
    if (password !== confirmPassword) return setError("Passwords do not match.");

    setBusy(true);
    try {
      onCreated(await api.createUser({ username, email, password, role }));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create user");
    } finally {
      setBusy(false);
    }
  }

  const selectedRole = ROLES.find((item) => item.value === role);

  return (
    <section className="border-b border-[#aaa6a1] bg-[#efedea] p-4 sm:p-5">
      <form onSubmit={submit} className="vv-panel space-y-5 p-5">
        <div>
          <p className="vv-kicker">Provision access</p>
          <h2 className="mt-1 text-lg font-black tracking-[-0.03em]">New operator account</h2>
          <p className="mt-1.5 text-xs text-[#676360]">
            Choose the minimum access the account needs. The password you set here is a handover
            credential — the owner is required to replace it at first sign-in.
          </p>
        </div>

        <div className="grid gap-5 sm:grid-cols-2">
          <label className="vv-field">
            <span className="vv-label">Username</span>
            <input
              autoFocus
              required
              minLength={3}
              maxLength={64}
              // The hyphen must be escaped: browsers compile `pattern` with the `v`
              // flag, which rejects an unescaped `-` in a character class and then
              // drops the attribute entirely.
              pattern="[A-Za-z0-9._\-]+"
              autoComplete="off"
              disabled={busy}
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              className="vv-input"
              placeholder="jane.smith"
            />
            <span className="vv-hint">Letters, digits, and . _ - only.</span>
          </label>

          <label className="vv-field">
            <span className="vv-label">Email</span>
            <input
              type="email"
              required
              maxLength={255}
              autoComplete="off"
              disabled={busy}
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              className="vv-input"
              placeholder="jane@example.test"
            />
          </label>

          <NewPasswordFields
            label="Temporary password"
            confirmLabel="Confirm temporary password"
            password={password}
            confirmPassword={confirmPassword}
            onPasswordChange={setPassword}
            onConfirmChange={setConfirmPassword}
            disabled={busy}
          />
        </div>

        <label className="vv-field max-w-sm">
          <span className="vv-label">Role</span>
          <select
            value={role}
            disabled={busy}
            onChange={(event) => setRole(event.target.value as UserRole)}
            className="vv-input"
          >
            {ROLES.map((item) => (
              <option key={item.value} value={item.value}>
                {item.label}
              </option>
            ))}
          </select>
          <span className="vv-hint">{selectedRole?.description}</span>
        </label>

        {error && (
          <p role="alert" className="vv-alert vv-alert-danger">
            {error}
          </p>
        )}

        <div className="flex justify-end">
          <button type="submit" disabled={busy} className="vv-button-primary">
            {busy ? "Creating…" : "Create user"}
          </button>
        </div>
      </form>
    </section>
  );
}
