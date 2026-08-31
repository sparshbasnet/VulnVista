import type {
  Finding,
  FindingStatus,
  Scan,
  Target,
  TargetCreatePayload,
  User,
  UserCreatePayload,
} from "../types";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = sessionStorage.getItem("vulnvista_access_token");
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init?.headers,
    },
  });
  if (response.status === 401 && path !== "/auth/login") {
    sessionStorage.removeItem("vulnvista_access_token");
    window.dispatchEvent(new Event("vulnvista:unauthorized"));
  }
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as { detail?: string } | null;
    throw new Error(body?.detail ?? `${init?.method ?? "GET"} ${path} failed: ${response.status}`);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export const api = {
  health: () => request<{ status: string; environment: string }>("/health"),
  login: (username: string, password: string) =>
    request<{ access_token: string; token_type: string }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  me: () => request<User>("/auth/me"),
  logout: () => request<void>("/auth/logout", { method: "POST" }),
  createUser: (payload: UserCreatePayload) =>
    request<User>("/auth/users", { method: "POST", body: JSON.stringify(payload) }),
  listTargets: () => request<Target[]>("/targets"),
  createTarget: (payload: TargetCreatePayload) =>
    request<Target>("/targets", { method: "POST", body: JSON.stringify(payload) }),
  allowTarget: (targetId: string) => request<Target>(`/targets/${targetId}/allow`, { method: "PATCH" }),
  listScans: () => request<Scan[]>("/scans"),
  getScan: (id: string) => request<Scan>(`/scans/${id}`),
  createScan: (payload: { target_id: string; scan_profile?: string; use_zap?: boolean }) =>
    request<Scan>("/scans", { method: "POST", body: JSON.stringify(payload) }),
  getScanFindings: (id: string) => request<Finding[]>(`/scans/${id}/findings`),
  listFindings: (params?: { target_id?: string; severity?: string }) => {
    const query = new URLSearchParams(params as Record<string, string>).toString();
    return request<Finding[]>(`/findings${query ? `?${query}` : ""}`);
  },
  updateFindingStatus: (id: string, finding_status: FindingStatus) =>
    request<Finding>(`/findings/${id}/status`, {
      method: "PATCH",
      body: JSON.stringify({ finding_status }),
    }),
};
