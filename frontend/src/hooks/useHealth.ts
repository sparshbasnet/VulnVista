import { useEffect, useState } from "react";
import { api } from "../services/api";

export type HealthState = "checking" | "online" | "offline";

export function useHealth(): HealthState {
  const [state, setState] = useState<HealthState>("checking");

  useEffect(() => {
    let cancelled = false;
    api
      .health()
      .then(() => !cancelled && setState("online"))
      .catch(() => !cancelled && setState("offline"));
    return () => {
      cancelled = true;
    };
  }, []);

  return state;
}
