"use client";

import type {
  AuditEntry,
  BodyPayload,
  CertificateAuthority,
  FlowDetail,
  FlowPage,
  FlowStats,
  LoginResult,
  PlatformStatus,
  PolicyRule,
  PolicyVerdict,
  ProxyNode,
  User,
} from "./types";

export const API_BASE =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") || "http://localhost:8000";

const TOKEN_KEY = "decrypt0rx.token";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null) {
  if (typeof window === "undefined") return;
  if (token) window.localStorage.setItem(TOKEN_KEY, token);
  else window.localStorage.removeItem(TOKEN_KEY);
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

/** Thrown when the session is gone; the shell redirects to /login on this. */
export class UnauthorizedError extends ApiError {}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, { ...init, headers });
  } catch {
    throw new ApiError(
      0,
      `Cannot reach the control plane at ${API_BASE}. Is the API container running?`,
    );
  }

  if (response.status === 401) {
    setToken(null);
    throw new UnauthorizedError(401, "Your session has expired. Please sign in again.");
  }
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail)) {
        // FastAPI validation errors: surface the field that failed.
        detail = body.detail
          .map((item: { loc?: string[]; msg?: string }) =>
            `${item.loc?.slice(1).join(".") ?? "input"}: ${item.msg ?? "invalid"}`,
          )
          .join("; ");
      }
    } catch {
      /* keep the status text */
    }
    throw new ApiError(response.status, detail);
  }

  if (response.status === 204) return undefined as T;
  const contentType = response.headers.get("content-type") || "";
  if (!contentType.includes("json")) return (await response.text()) as T;
  return (await response.json()) as T;
}

const json = (body: unknown) => ({ body: JSON.stringify(body) });

export const api = {
  login: (email: string, password: string) =>
    request<LoginResult>("/api/v1/auth/login", { method: "POST", ...json({ email, password }) }),
  me: () => request<User>("/api/v1/auth/me"),
  changePassword: (current_password: string, new_password: string) =>
    request<void>("/api/v1/auth/change-password", {
      method: "POST",
      ...json({ current_password, new_password }),
    }),

  status: () => request<PlatformStatus>("/api/v1/status"),
  nodes: () => request<ProxyNode[]>("/api/v1/nodes"),
  audit: (limit = 100) => request<AuditEntry[]>(`/api/v1/audit?limit=${limit}`),

  listCAs: () => request<CertificateAuthority[]>("/api/v1/ca"),
  generateCA: (payload: Record<string, unknown>) =>
    request<CertificateAuthority>("/api/v1/ca/generate", { method: "POST", ...json(payload) }),
  importCA: (payload: Record<string, unknown>) =>
    request<CertificateAuthority>("/api/v1/ca/import", { method: "POST", ...json(payload) }),
  activateCA: (id: number) =>
    request<CertificateAuthority>(`/api/v1/ca/${id}/activate`, { method: "POST" }),
  deleteCA: (id: number) => request<void>(`/api/v1/ca/${id}`, { method: "DELETE" }),
  caDownloadUrl: (id: number) => `${API_BASE}/api/v1/ca/${id}/certificate`,
  publicRootUrl: () => `${API_BASE}/api/v1/ca/public/root.crt`,

  listPolicies: () => request<PolicyRule[]>("/api/v1/policies"),
  createPolicy: (payload: Record<string, unknown>) =>
    request<PolicyRule>("/api/v1/policies", { method: "POST", ...json(payload) }),
  updatePolicy: (id: number, payload: Record<string, unknown>) =>
    request<PolicyRule>(`/api/v1/policies/${id}`, { method: "PATCH", ...json(payload) }),
  deletePolicy: (id: number) => request<void>(`/api/v1/policies/${id}`, { method: "DELETE" }),
  testPolicy: (payload: { host: string; port?: number; client_ip?: string }) =>
    request<PolicyVerdict>("/api/v1/policies/test", { method: "POST", ...json(payload) }),

  listFlows: (query: string) => request<FlowPage>(`/api/v1/flows${query}`),
  flowStats: (minutes: number) =>
    request<FlowStats>(`/api/v1/flows/stats?window_minutes=${minutes}`),
  flow: (id: string) => request<FlowDetail>(`/api/v1/flows/${id}`),
  flowBody: (id: string, direction: "request" | "response") =>
    request<BodyPayload>(`/api/v1/flows/${id}/body/${direction}`),
  flowRawUrl: (id: string) => `${API_BASE}/api/v1/flows/${id}/raw`,
  purgeFlows: () => request<void>("/api/v1/flows", { method: "DELETE" }),

  listUsers: () => request<User[]>("/api/v1/users"),
  createUser: (payload: Record<string, unknown>) =>
    request<User>("/api/v1/users", { method: "POST", ...json(payload) }),
  updateUser: (id: number, payload: Record<string, unknown>) =>
    request<User>(`/api/v1/users/${id}`, { method: "PATCH", ...json(payload) }),
  deleteUser: (id: number) => request<void>(`/api/v1/users/${id}`, { method: "DELETE" }),
};

/** WebSocket URL for the live flow feed; the token rides as a query param
 *  because browsers cannot set headers on a WebSocket handshake. */
export function flowStreamUrl(): string | null {
  const token = getToken();
  if (!token) return null;
  const base = API_BASE.replace(/^http/, "ws");
  return `${base}/api/v1/ws/flows?token=${encodeURIComponent(token)}`;
}
