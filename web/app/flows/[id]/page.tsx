"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { PageHeader, Shell } from "@/components/shell";
import {
  ActionBadge,
  Alert,
  Badge,
  Button,
  Card,
  Spinner,
  StatusBadge,
  formatBytes,
  formatDateTime,
} from "@/components/ui";
import { api } from "@/lib/api";
import type { BodyPayload, FlowDetail } from "@/lib/types";

export default function FlowDetailPage() {
  return (
    <Shell>
      <Detail />
    </Shell>
  );
}

function Detail() {
  const params = useParams<{ id: string }>();
  const [flow, setFlow] = useState<FlowDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .flow(params.id)
      .then(setFlow)
      .catch((err) => setError(err instanceof Error ? err.message : "Not found"));
  }, [params.id]);

  if (error) {
    return (
      <>
        <PageHeader title="Flow" />
        <div className="p-8">
          <Alert>{error}</Alert>
        </div>
      </>
    );
  }
  if (!flow) return <Spinner label="Loading flow" />;

  return (
    <>
      <PageHeader
        title={`${flow.method ?? "CONNECT"} ${flow.host}`}
        description={flow.path ?? `${flow.host}:${flow.port}`}
      >
        <Link href="/flows">
          <Button>← Back to traffic</Button>
        </Link>
        <a href={api.flowRawUrl(flow.id)} target="_blank" rel="noreferrer">
          <Button variant="primary">Raw SSL dump</Button>
        </a>
      </PageHeader>

      <div className="space-y-6 p-8">
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge code={flow.status_code} />
          <ActionBadge action={flow.action} />
          {flow.intercepted ? <Badge tone="info">decrypted</Badge> : <Badge>tunnelled</Badge>}
          {flow.redacted && <Badge tone="warn">redacted</Badge>}
          {flow.bodies_truncated && <Badge tone="warn">truncated</Badge>}
          {flow.rule_name && <Badge tone="violet">rule: {flow.rule_name}</Badge>}
        </div>

        {flow.error && <Alert>{flow.error}</Alert>}

        <div className="grid gap-6 lg:grid-cols-4">
          <Card title="Connection" className="lg:col-span-1">
            <dl className="space-y-2 text-sm">
              <Item label="Started" value={formatDateTime(flow.started_at)} />
              <Item label="Duration" value={flow.duration_ms === null ? "-" : `${flow.duration_ms} ms`} />
              <Item label="Client" value={`${flow.client_ip}:${flow.client_port}`} mono />
              <Item label="Upstream" value={flow.upstream_ip ?? "-"} mono />
              <Item label="Target" value={`${flow.host}:${flow.port}`} mono />
              <Item label="SNI" value={flow.sni ?? "-"} mono />
              <Item label="TLS" value={flow.tls_version ?? "-"} />
              <Item label="Cipher" value={flow.tls_cipher ?? "-"} mono />
              <Item label="ALPN" value={flow.alpn ?? "-"} />
              <Item label="Proxy node" value={flow.proxy_node ?? "-"} mono />
              <Item
                label="Transferred"
                value={`${formatBytes(flow.request_size)} up / ${formatBytes(flow.response_size)} down`}
              />
            </dl>
          </Card>

          <div className="space-y-6 lg:col-span-3">
            <div className="grid gap-6 xl:grid-cols-2">
              <Card title="Request headers">
                <HeaderTable headers={flow.request_headers} />
              </Card>
              <Card title="Response headers">
                <HeaderTable headers={flow.response_headers} />
              </Card>
            </div>

            <BodyPanel
              flowId={flow.id}
              direction="request"
              available={flow.has_request_body}
              contentType={flow.request_content_type}
            />
            <BodyPanel
              flowId={flow.id}
              direction="response"
              available={flow.has_response_body}
              contentType={flow.response_content_type}
            />
          </div>
        </div>
      </div>
    </>
  );
}

function Item({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide text-ink-400">{label}</dt>
      <dd className={`break-all text-ink-100 ${mono ? "font-mono text-xs" : "text-sm"}`}>{value}</dd>
    </div>
  );
}

function HeaderTable({ headers }: { headers: Record<string, string> | null }) {
  if (!headers || Object.keys(headers).length === 0) {
    return <p className="text-sm text-ink-400">None recorded.</p>;
  }
  return (
    <div className="max-h-72 overflow-y-auto">
      <table className="w-full text-left font-mono text-xs">
        <tbody>
          {Object.entries(headers).map(([name, value]) => (
            <tr key={name} className="border-b border-ink-800/60 last:border-0">
              <td className="w-1/3 py-1.5 pr-3 align-top text-accent">{name}</td>
              <td className={`py-1.5 break-all ${value.includes("REDACTED") ? "text-warn" : "text-ink-200"}`}>
                {value}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function BodyPanel({
  flowId,
  direction,
  available,
  contentType,
}: {
  flowId: string;
  direction: "request" | "response";
  available: boolean;
  contentType: string | null;
}) {
  const [body, setBody] = useState<BodyPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [pretty, setPretty] = useState(true);

  async function load() {
    setLoading(true);
    try {
      setBody(await api.flowBody(flowId, direction));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load body");
    } finally {
      setLoading(false);
    }
  }

  const title = direction === "request" ? "Request body" : "Response body";

  if (!available) {
    return (
      <Card title={title}>
        <p className="text-sm text-ink-400">
          No body captured.{" "}
          <Link href="/policies" className="text-accent hover:underline">
            Enable body capture
          </Link>{" "}
          on a policy rule matching this host to record payloads.
        </p>
      </Card>
    );
  }

  return (
    <Card
      title={title}
      action={
        <div className="flex items-center gap-2">
          {contentType && <span className="text-xs text-ink-400">{contentType}</span>}
          {body?.encoding === "utf-8" && isJson(contentType) && (
            <Button variant="subtle" onClick={() => setPretty((value) => !value)}>
              {pretty ? "Raw" : "Pretty"}
            </Button>
          )}
          {!body && (
            <Button variant="ghost" onClick={load} disabled={loading}>
              {loading ? "Loading…" : "Load body"}
            </Button>
          )}
        </div>
      }
    >
      {error && <Alert>{error}</Alert>}
      {!body && !error && <p className="text-sm text-ink-400">Bodies load on demand.</p>}
      {body && (
        <>
          <p className="mb-2 text-xs text-ink-400">
            {formatBytes(body.size)}
            {body.truncated && " · truncated at the capture limit"}
            {body.encoding === "base64" && " · binary, shown base64-encoded"}
          </p>
          <pre className="max-h-[32rem] overflow-auto rounded-lg bg-ink-950 p-4 font-mono text-xs leading-relaxed text-ink-200">
            {render(body, pretty)}
          </pre>
        </>
      )}
    </Card>
  );
}

function isJson(contentType: string | null): boolean {
  return (contentType || "").toLowerCase().includes("json");
}

function render(body: BodyPayload, pretty: boolean): string {
  if (body.encoding !== "utf-8" || !pretty || !isJson(body.content_type)) return body.content;
  try {
    return JSON.stringify(JSON.parse(body.content), null, 2);
  } catch {
    return body.content; // truncated capture, or not actually JSON
  }
}
