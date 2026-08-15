export const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;

export const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: "bg-red-100 text-red-800 ring-1 ring-inset ring-red-200",
  HIGH: "bg-orange-100 text-orange-800 ring-1 ring-inset ring-orange-200",
  MEDIUM: "bg-amber-100 text-amber-800 ring-1 ring-inset ring-amber-200",
  LOW: "bg-neutral-100 text-neutral-600 ring-1 ring-inset ring-neutral-200",
  INFO: "bg-sky-100 text-sky-700 ring-1 ring-inset ring-sky-200",
};

export const SEVERITY_BAR: Record<string, string> = {
  CRITICAL: "bg-red-800",
  HIGH: "bg-red-500",
  MEDIUM: "bg-amber-400",
  LOW: "bg-neutral-400",
  INFO: "bg-neutral-200",
};

export const VALIDATION_BADGE: Record<string, string> = {
  CONFIRMED: "bg-red-50 text-red-700 ring-1 ring-inset ring-red-200",
  SUSPECTED: "bg-amber-50 text-amber-700 ring-1 ring-inset ring-amber-200",
  INCONCLUSIVE: "bg-neutral-100 text-neutral-600 ring-1 ring-inset ring-neutral-200",
  NOT_DETECTED: "bg-emerald-50 text-emerald-700 ring-1 ring-inset ring-emerald-200",
  ERROR: "bg-neutral-100 text-neutral-500 ring-1 ring-inset ring-neutral-200",
};

export const STATUS_OPTIONS = [
  "OPEN",
  "IN_PROGRESS",
  "REMEDIATED",
  "ACCEPTED_RISK",
  "FALSE_POSITIVE",
] as const;
