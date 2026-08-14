import type { Finding, Scan, Target, TargetCreatePayload } from "../types";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!response.ok) {
    throw new Error(`${init?.method ?? "GET"} ${path} failed: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  health: () => request<{ status: string; environment: string }>("/health"),
  listTargets: () => request<Target[]>("/targets"),
  createTarget: (payload: TargetCreatePayload) =>
    request<Target>("/targets", { method: "POST", body: JSON.stringify(payload) }),
  listScans: () => request<Scan[]>("/scans"),
  getScan: (id: string) => request<Scan>(`/scans/${id}`),
  createScan: (payload: { target_id: string; scan_profile?: string }) =>
    request<Scan>("/scans", { method: "POST", body: JSON.stringify(payload) }),
  getScanFindings: (id: string) => request<Finding[]>(`/scans/${id}/findings`),
  listFindings: (params?: { target_id?: string; severity?: string }) => {
    const query = new URLSearchParams(params as Record<string, string>).toString();
    return request<Finding[]>(`/findings${query ? `?${query}` : ""}`);
  },
};
