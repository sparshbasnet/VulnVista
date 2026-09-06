import PageHeader from "../components/PageHeader";
import ChangePasswordForm from "../components/ChangePasswordForm";
import { useAuth } from "../auth/useAuth";

const ROLE_SUMMARY: Record<string, string> = {
  ADMIN: "Full analyst access plus user administration.",
  ANALYST: "Register targets, run scans, and update finding status.",
  VIEWER: "Read-only access to targets, scans, and findings.",
};

function formatDateTime(value: string | null | undefined): string {
  if (!value) return "Never";
  return new Intl.DateTimeFormat(undefined, {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

function Detail({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="bg-[#f7f6f4] p-4">
      <p className="vv-label">{label}</p>
      <p className="mt-1 truncate text-sm font-black tracking-[-0.02em]" title={value}>
        {value}
      </p>
      {sub && <p className="mt-1 text-[10px] leading-snug text-[#676360]">{sub}</p>}
    </div>
  );
}

export default function Account() {
  const { user, logout } = useAuth();
  if (!user) return null;

  return (
    <div className="bg-[#f7f6f4]">
      <PageHeader
        eyebrow="Your account"
        title={user.username}
        description="Session details and credential settings for the account you are signed in as."
        right={
          <button
            type="button"
            onClick={() => void logout()}
            className="vv-button-secondary mx-4 self-center"
          >
            Sign out
          </button>
        }
      />

      <section className="grid grid-cols-2 gap-px border-b border-[#aaa6a1] bg-[#aaa6a1] lg:grid-cols-4">
        <Detail label="Email" value={user.email} />
        <Detail label="Role" value={user.role} sub={ROLE_SUMMARY[user.role]} />
        <Detail label="Last sign-in" value={formatDateTime(user.last_login_at)} />
        <Detail
          label="Password changed"
          value={formatDateTime(user.password_changed_at)}
          sub={user.password_changed_at ? undefined : "Still on the password you were issued."}
        />
      </section>

      <section className="p-4 sm:p-5 lg:p-6">
        <div className="grid gap-5 lg:grid-cols-[minmax(0,24rem)_minmax(0,1fr)]">
          <div className="vv-panel p-5">
            <p className="vv-kicker">Credentials</p>
            <h2 className="mt-1.5 mb-5 text-lg font-black tracking-[-0.03em]">Change password</h2>
            <ChangePasswordForm />
          </div>

          <div className="vv-panel p-5">
            <p className="vv-kicker">What your role allows</p>
            <h2 className="mt-1.5 text-lg font-black tracking-[-0.03em]">Access summary</h2>
            <dl className="mt-4 divide-y divide-[#d8d4cf] text-xs">
              {Object.entries(ROLE_SUMMARY).map(([role, summary]) => (
                <div key={role} className="flex gap-4 py-3">
                  <dt
                    className={`w-24 shrink-0 text-[10px] font-black uppercase tracking-wider ${
                      role === user.role ? "text-[#a61b0d]" : "text-[#85817d]"
                    }`}
                  >
                    {role}
                    {role === user.role && <span className="block font-bold">— you</span>}
                  </dt>
                  <dd className={role === user.role ? "text-[#171616]" : "text-[#676360]"}>
                    {summary}
                  </dd>
                </div>
              ))}
            </dl>
            <p className="vv-hint mt-4">
              Roles are assigned by an administrator. If you need different access, ask one to change
              it — you cannot change your own role.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}
