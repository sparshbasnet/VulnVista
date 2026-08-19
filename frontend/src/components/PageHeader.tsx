import type { ReactNode } from "react";

export default function PageHeader({
  eyebrow,
  title,
  description,
  right,
}: {
  eyebrow: string;
  title: string;
  description?: string;
  right?: ReactNode;
}) {
  return (
    <header className="flex min-h-[94px] flex-wrap items-end justify-between gap-5 border-b border-[#8f8b87] bg-[#f7f6f4] px-4 py-5 sm:px-6 lg:px-7">
      <div className="min-w-0">
        <p className="vv-kicker">{eyebrow}</p>
        <h1 className="mt-1 text-[clamp(1.75rem,3vw,2.35rem)] font-black leading-none tracking-[-0.045em] text-[#171616]">
          {title}
        </h1>
        {description && <p className="mt-2 max-w-2xl text-xs leading-relaxed text-[#676360]">{description}</p>}
      </div>
      {right && (
        <div className="flex max-w-full flex-wrap items-stretch divide-x divide-[#aaa6a1] text-xs">
          {right}
        </div>
      )}
    </header>
  );
}
