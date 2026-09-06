import {
  createContext,
  createElement,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import type { PropsWithChildren } from "react";
import { api } from "../services/api";
import type { Finding, Scan, Target } from "../types";

interface AppDataValue {
  targets: Target[];
  scans: Scan[];
  findings: Finding[];
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
  replaceFinding: (finding: Finding) => void;
}

const AppDataContext = createContext<AppDataValue | null>(null);

export function AppDataProvider({ children }: PropsWithChildren) {
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [nextTargets, nextScans, nextFindings] = await Promise.all([
        api.listTargets(),
        api.listScans(),
        api.listFindings(),
      ]);
      setTargets(nextTargets);
      setScans(nextScans);
      setFindings(nextFindings);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const replaceFinding = useCallback((next: Finding) => {
    setFindings((current) => current.map((finding) => (finding.id === next.id ? next : finding)));
  }, []);

  const value = useMemo(
    () => ({ targets, scans, findings, loading, error, refresh, replaceFinding }),
    [targets, scans, findings, loading, error, refresh, replaceFinding],
  );

  return createElement(AppDataContext.Provider, { value }, children);
}

export function useAppData(): AppDataValue {
  const value = useContext(AppDataContext);
  if (!value) throw new Error("useAppData must be used inside AppDataProvider");
  return value;
}
