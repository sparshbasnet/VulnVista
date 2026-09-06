import type {
  Discovery,
  Finding,
  FindingStatus,
  PasswordResetIssued,
  Scan,
  Target,
  TargetCreatePayload,
  TokenResponse,
  User,
  UserCreatePayload,
  UserUpdatePayload,
} from "../types";
import { UNAUTHORIZED_EVENT, clearToken, readToken } from "../auth/token";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? "http://localhost:9000/api";

// Reaching these without a session is normal, so a 401 from them is a failed
// attempt rather than an expired session to sign the user out of.
const PUBLIC_PATHS = new Set([
  "/auth/login",
  "/auth/password-reset/request",
  "/auth/password-reset/confirm",
]);

/**
 * FastAPI answers with a plain string for handled errors and a list of
 * `{ loc, msg }` entries for 422 validation failures. Flatten both to something
 * a form can put in front of the user.
 */
function describeError(detail: unknown): string | null {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    const messages = detail
      .map((entry) =>
        typeof entry === "object" && entry !== null && "msg" in entry
          ? String((entry as { msg: unknown }).msg).replace(/^Value error, /, "")
          : null,
      )
      .filter((message): message is string => Boolean(message));
    if (messages.length > 0) return messages.join(" ");
  }
  return null;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = readToken();
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init?.headers,
    },
  });
  if (response.status === 401 && !PUBLIC_PATHS.has(path)) {
    clearToken();
    window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
  }
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as {
      detail?: unknown;
    } | null;
    throw new Error(
      describeError(body?.detail) ??
        `${init?.method ?? "GET"} ${path} failed: ${response.status}`,
    );
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export const api = {
  health: () => request<{ status: string; environment: string }>("/health"),
  login: (username: string, password: string) =>
    request<TokenResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  me: () => request<User>("/auth/me"),
  logout: () => request<void>("/auth/logout", { method: "POST" }),
  changePassword: (current_password: string, new_password: string) =>
    request<TokenResponse>("/auth/me/password", {
      method: "POST",
      body: JSON.stringify({ current_password, new_password }),
    }),
  requestPasswordReset: (identity: string) =>
    request<{ detail: string }>("/auth/password-reset/request", {
      method: "POST",
      body: JSON.stringify({ identity }),
    }),
  confirmPasswordReset: (token: string, new_password: string) =>
    request<void>("/auth/password-reset/confirm", {
      method: "POST",
      body: JSON.stringify({ token, new_password }),
    }),
  listUsers: () => request<User[]>("/auth/users"),
  createUser: (payload: UserCreatePayload) =>
    request<User>("/auth/users", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updateUser: (id: string, payload: UserUpdatePayload) =>
    request<User>(`/auth/users/${id}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  issuePasswordReset: (id: string) =>
    request<PasswordResetIssued>(`/auth/users/${id}/password-reset`, {
      method: "POST",
    }),
  listTargets: () => request<Target[]>("/targets"),
  deleteTarget: (id: string) => request<void>(`/targets/${id}`, { method: "DELETE" }),
  createTarget: (payload: TargetCreatePayload) =>
    request<Target>("/targets", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  createDiscovery: (payload: { target_id: string }) =>
    request<Discovery>("/discoveries", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  getDiscovery: (id: string) => request<Discovery>(`/discoveries/${id}`),
  listScans: () => request<Scan[]>("/scans"),
  getScan: (id: string) => request<Scan>(`/scans/${id}`),
  createScan: (payload: {
    target_id: string;
    scan_profile?: string;
    in_scope_paths?: string[];
    out_of_scope_paths?: string[];
  }) => request<Scan>("/scans", { method: "POST", body: JSON.stringify(payload) }),
  getScanFindings: (id: string) => request<Finding[]>(`/scans/${id}/findings`),
  listFindings: (params?: { target_id?: string; severity?: string }) => {
    const query = new URLSearchParams(
      params as Record<string, string>,
    ).toString();
    return request<Finding[]>(`/findings${query ? `?${query}` : ""}`);
  },
  updateFindingStatus: (id: string, finding_status: FindingStatus) =>
    request<Finding>(`/findings/${id}/status`, {
      method: "PATCH",
      body: JSON.stringify({ finding_status }),
    }),
};
