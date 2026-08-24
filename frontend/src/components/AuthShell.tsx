import type { ReactNode } from "react";
import { Link } from "react-router-dom";

/**
 * Frame for the signed-out pages. Layout only renders once a session exists, so
 * login, recovery, and reset would otherwise each invent their own chrome.
 */
export default function AuthShell({
  eyebrow,
  title,
  description,
  children,
  footer,
}: {
  eyebrow: string;
  title: string;
  description: string;
  children: ReactNode;
  footer?: ReactNode;
}) {
  return (
    <main className="grid min-h-screen bg-[#e9e7e4] text-[#171616] lg:grid-cols-[minmax(0,1fr)_minmax(0,1.05fr)]">
      <section className="relative hidden flex-col justify-between border-r border-[#8f8b87] bg-[#f7f6f4] p-10 lg:flex">
        <div className="absolute inset-y-0 left-0 w-1 bg-[#f0321d]" aria-hidden="true" />
        <div>
          <span className="text-[22px] font-black tracking-[-0.04em]">
            VULN<span className="text-[#f0321d]">VISTA</span>
          </span>
          <p className="mt-1 text-[9px] font-semibold uppercase tracking-[0.18em] text-[#676360]">
            15-detector scanner
          </p>
        </div>
        <div className="max-w-md">
          <p className="vv-kicker">Controlled assessment</p>
          <p className="mt-3 text-[clamp(1.6rem,2.6vw,2.2rem)] font-black leading-[1.05] tracking-[-0.045em]">
            Detect, validate, and triage findings from approved lab targets.
          </p>
          <p className="mt-4 text-xs leading-relaxed text-[#676360]">
            Every target is an authorization-scoped record, and every action is tied to the operator
            account that took it. Sign in with the account issued to you.
          </p>
        </div>
        <p className="text-[10px] leading-relaxed text-[#676360]">
          Lab scope only · authorization enforced per target
        </p>
      </section>

      <section className="flex items-center justify-center px-5 py-10 sm:px-8">
        <div className="w-full max-w-[26rem]">
          <div className="mb-6 lg:hidden">
            <span className="text-[19px] font-black tracking-[-0.04em]">
              VULN<span className="text-[#f0321d]">VISTA</span>
            </span>
          </div>

          <div className="vv-panel vv-panel-accent p-7">
            <p className="vv-kicker">{eyebrow}</p>
            <h1 className="mt-2 text-[clamp(1.6rem,3vw,2.05rem)] font-black leading-none tracking-[-0.045em]">
              {title}
            </h1>
            <p className="mt-2.5 text-xs leading-relaxed text-[#676360]">{description}</p>
            <div className="mt-6">{children}</div>
          </div>

          {footer && (
            <div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-[11px] text-[#676360]">
              {footer}
            </div>
          )}
        </div>
      </section>
    </main>
  );
}

/** A text link styled for the auth footers. */
export function AuthLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link to={to} className="font-bold text-[#a61b0d] underline-offset-2 hover:underline">
      {children}
    </Link>
  );
}
