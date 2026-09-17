export type Role = "admin" | "operator" | "viewer";
export type PolicyAction = "intercept" | "bypass" | "block";

export interface User {
  id: number;
  email: string;
  full_name: string | null;
  role: Role;
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface LoginResult {
  access_token: string;
  token_type: string;
  expires_at: string;
  user: User;
}

export interface CertificateAuthority {
  id: number;
  name: string;
  subject: string;
  fingerprint_sha256: string;
  key_algorithm: string;
  not_before: string;
  not_after: string;
  is_active: boolean;
  source: "generated" | "imported";
  created_at: string;
  created_by: string | null;
  cert_pem: string;
}

export interface PolicyRule {
  id: number;
  name: string;
  description: string | null;
  priority: number;
  enabled: boolean;
  host_pattern: string;
  client_cidr: string | null;
  port: number | null;
  action: PolicyAction;
  capture_bodies: boolean;
  capture_max_bytes: number;
  redact: boolean;
  created_at: string;
  updated_at: string;
}

export interface FlowSummary {
  id: string;
  started_at: string;
  duration_ms: number | null;
  client_ip: string;
  host: string;
  port: number;
  scheme: string;
  method: string | null;
  path: string | null;
  status_code: number | null;
  request_size: number;
  response_size: number;
  action: PolicyAction;
  intercepted: boolean;
  rule_name: string | null;
  error: string | null;
}

export interface FlowDetail extends FlowSummary {
  connection_id: string;
  ended_at: string | null;
  client_port: number;
  sni: string | null;
  upstream_ip: string | null;
  http_version: string | null;
  request_headers: Record<string, string> | null;
  response_headers: Record<string, string> | null;
  request_content_type: string | null;
  response_content_type: string | null;
  has_request_body: boolean;
  has_response_body: boolean;
  bodies_truncated: boolean;
  redacted: boolean;
  tls_version: string | null;
  tls_cipher: string | null;
  alpn: string | null;
  proxy_node: string | null;
}

export interface FlowPage {
  items: FlowSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface FlowStats {
  window_minutes: number;
  total: number;
  intercepted: number;
  blocked: number;
  bypassed: number;
  errors: number;
  bytes_in: number;
  bytes_out: number;
  top_hosts: { host: string; count: number }[];
  status_breakdown: { bucket: number; count: number }[];
  timeline: { ts: string; count: number }[];
}

export interface BodyPayload {
  flow_id: string;
  direction: "request" | "response";
  content_type: string | null;
  size: number;
  truncated: boolean;
  encoding: "utf-8" | "base64";
  content: string;
}

export interface ProxyNode {
  id: number;
  node_id: string;
  version: string | null;
  listen: string | null;
  active_connections: number;
  total_flows: number;
  policy_version: number;
  started_at: string;
  last_seen_at: string;
  healthy: boolean;
}

export interface PlatformStatus {
  ca: {
    name: string;
    subject: string;
    fingerprint: string;
    not_after: string;
    expires_in_days: number;
  } | null;
  enabled_rules: number;
  proxy_nodes: {
    node_id: string;
    listen: string | null;
    active_connections: number;
    total_flows: number;
    policy_version: number;
  }[];
  active_connections: number;
  flows_last_hour: number;
  interception_ready: boolean;
}

export interface AuditEntry {
  id: number;
  created_at: string;
  actor: string;
  action: string;
  target: string | null;
  detail: Record<string, unknown> | null;
  client_ip: string | null;
}

export interface PolicyVerdict {
  action: PolicyAction;
  capture_bodies: boolean;
  redact: boolean;
  matched_rule_id: number | null;
  matched_rule_name: string | null;
}
