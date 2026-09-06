import { useEffect, useRef, useState } from "react";
import { downloadFindingsReport, type ReportFormat } from "../lib/report";
import type { Finding } from "../types";

const FORMATS: { format: ReportFormat; label: string; hint: string }[] = [
  { format: "pdf", label: "PDF", hint: "Formatted document" },
  { format: "xls", label: "Excel", hint: "Opens as a spreadsheet" },
  { format: "csv", label: "CSV", hint: "Raw data" },
];

export default function ReportMenu({
  findings,
  disabled,
  buttonClassName,
  label,
  menuPlacement = "down",
  menuAlign = "left",
}: {
  findings: Finding[];
  disabled?: boolean;
  buttonClassName: string;
  label: string;
  menuPlacement?: "up" | "down";
  menuAlign?: "left" | "right";
}) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  const choose = (format: ReportFormat) => {
    downloadFindingsReport(findings, format);
    setOpen(false);
  };

  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((prev) => !prev)}
        disabled={disabled}
        aria-haspopup="menu"
        aria-expanded={open}
        className={buttonClassName}
      >
        {label}
      </button>
      {open && (
        <div
          role="menu"
          aria-label="Report format"
          className={`absolute z-50 w-48 border border-[#171616] bg-white text-left shadow-[3px_3px_0_0_#171616] ${
            menuPlacement === "up" ? "bottom-full mb-2" : "top-full mt-2"
          } ${menuAlign === "right" ? "right-0" : "left-0"}`}
        >
          <p className="border-b border-[#d8d4cf] px-3 py-2 text-[9px] font-extrabold uppercase tracking-[0.12em] text-[#676360]">
            Choose format
          </p>
          {FORMATS.map(({ format, label: formatLabel, hint }) => (
            <button
              key={format}
              type="button"
              role="menuitem"
              onClick={() => choose(format)}
              className="group flex w-full flex-col items-start gap-0.5 px-3 py-2 text-left text-[11px] font-bold uppercase tracking-wide text-[#171616] hover:bg-[#f0321d] hover:text-white"
            >
              {formatLabel}
              <span className="text-[9px] font-semibold normal-case tracking-normal text-[#676360] group-hover:text-white">
                {hint}
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
