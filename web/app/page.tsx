"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { Shell, PageHeader } from "@/components/shell";
import {
  ActionBadge,
  Alert,
  Badge,
  Card,
  Empty,
  Spinner,
  Stat,
  StatusBadge,
  formatBytes,
  formatTime,
  relativeTime,
} from "@/components/ui";
import { api, flowStreamUrl } from "@/lib/api";
import type { FlowStats, FlowSummary, PlatformStatus } from "@/lib/types";

const WINDOW_MINUTES = 60;
const MAX_LIVE_ROWS = 40;

export default function DashboardPage() {
  return (
    <Shell>
      <Dashboard />
    </Shell>
  );
}

function Dashboard() {
  const [status, setStatus] = useState<PlatformStatus | null>(null);
  const [stats, setStats] = useState<FlowStats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [live, setLive] = useState<FlowSummary[]>([]);
  const [streamState, setStreamState] = useState<"connecting" | "live" | "offline">(
    "connecting",
  );

  const refresh = useCallback(async () => {
    try {
      const [platform, flowStats] = await Promise.all([
        api.status(),
        api.flowStats(WINDOW_MINUTES),
      ]);
      setStatus(platform);
      setStats(flowStats);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load dashboard");
    }
  }, []);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 10_000);
    return () => clearInterval(timer);
  }, [refresh]);

  useLiveFlows(setLive, setStreamState);

  if (error) {
    return (
      <>
        <PageHeader title="Dashboard" />
        <div className="p-8">
          <Alert>{error}</Alert>
        </div>
      </>
    );
  }
  if (!status || !stats) {
    return (
      <>
        <PageHeader title="Dashboard" />
        <Spinner label="Loading platform status" />
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Dashboard"
        description={`Traffic and platform health over the last ${WINDOW_MINUTES} minutes.`}
      >
        <Badge tone={streamState === "live" ? "good" : streamState === "connecting" ? "warn" : "neutral"}>
          {streamState === "live" ? "● live" : streamState === "connecting" ? "connecting" : "polling"}
        </Badge>
      </PageHeader>

      <div className="space-y-6 p-8">
        {!status.interception_ready && <ReadinessBanner status={status} />}

        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
          <Stat label="Flows / hour" value={status.flows_last_hour.toLocaleString()} />
          <Stat
            label="Decrypted"
            value={stats.intercepted.toLocaleString()}
            sub={`${stats.bypassed.toLocaleString()} tunnelled`}
            tone="info"
          />
          <Stat label="Blocked" value={stats.blocked.toLocaleString()} tone={stats.blocked ? "warn" : "neutral"} />
          <Stat label="Errors" value={stats.errors.toLocaleString()} tone={stats.errors ? "bad" : "good"} />
          <Stat
            label="Open connections"
            value={status.active_connections}
            sub={`${status.proxy_nodes.length} proxy node${status.proxy_nodes.length === 1 ? "" : "s"}`}
          />
        </div>

        <div className="grid gap-6 lg:grid-cols-3">
          <Card
            title="Live traffic"
            className="lg:col-span-2"
            action={
              <Link href="/flows" className="text-xs text-accent hover:underline">
                Open traffic explorer →
              </Link>
            }
          >
            {live.length === 0 ? (
              <Empty
                title="No traffic yet"
                hint="Point a client at the proxy (HTTPS_PROXY=http://<host>:8080) and requests will appear here as they happen."
              />
            ) : (
              <div className="-mx-2 max-h-[26rem] overflow-y-auto">
                <table className="w-full text-left text-sm">
                  <tbody>
                    {live.map((flow) => (
                      <tr key={flow.id} className="row-in border-b border-ink-800/60 last:border-0">
                        <td className="px-2 py-2 font-mono text-xs text-ink-400">
                          {formatTime(flow.started_at)}
                        </td>
                        <td className="px-2 py-2">
                          <StatusBadge code={flow.status_code} />
                        </td>
                        <td className="px-2 py-2 font-mono text-xs text-violet">
                          {flow.method ?? "-"}
                        </td>
                        <td className="max-w-md truncate px-2 py-2">
                          <Link href={`/flows/${flow.id}`} className="hover:text-accent">
                            <span className="text-ink-200">{flow.host}</span>
                            <span className="text-ink-400">{flow.path ?? ""}</span>
                          </Link>
                        </td>
                        <td className="px-2 py-2 text-right">
                          <ActionBadge action={flow.action} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          <div className="space-y-6">
            <Card title="Top hosts">
              {stats.top_hosts.length === 0 ? (
                <p className="text-sm text-ink-400">Nothing recorded yet.</p>
              ) : (
                <ul className="space-y-2">
                  {stats.top_hosts.map((entry) => {
                    const share = (entry.count / (stats.top_hosts[0]?.count || 1)) * 100;
                    return (
                      <li key={entry.host} className="space-y-1">
                        <div className="flex justify-between text-xs">
                          <span className="truncate text-ink-200">{entry.host}</span>
                          <span className="tabular-nums text-ink-400">{entry.count}</span>
                        </div>
                        <div className="h-1.5 overflow-hidden rounded bg-ink-800">
                          <div className="h-full rounded bg-accent-dim" style={{ width: `${share}%` }} />
                        </div>
                      </li>
                    );
                  })}
                </ul>
              )}
            </Card>

            <Card title="Transfer">
              <dl className="space-y-2 text-sm">
                <Row label="Uploaded" value={formatBytes(stats.bytes_in)} />
                <Row label="Downloaded" value={formatBytes(stats.bytes_out)} />
                <Row label="Enabled rules" value={String(status.enabled_rules)} />
              </dl>
            </Card>
          </div>
        </div>

        <Card title="Proxy fleet">
          {status.proxy_nodes.length === 0 ? (
            <Empty
              title="No proxy node has checked in"
              hint="Each proxy heartbeats every 10 seconds. If this stays empty, check that the proxy container can reach Postgres."
            />
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase tracking-wide text-ink-400">
                <tr>
                  <th className="pb-2">Node</th>
                  <th className="pb-2">Listening</th>
                  <th className="pb-2 text-right">Connections</th>
                  <th className="pb-2 text-right">Flows</th>
                  <th className="pb-2 text-right">Policy version</th>
                </tr>
              </thead>
              <tbody>
                {status.proxy_nodes.map((node) => (
                  <tr key={node.node_id} className="border-t border-ink-800">
                    <td className="py-2 font-mono text-xs">{node.node_id}</td>
                    <td className="py-2 font-mono text-xs text-ink-400">{node.listen}</td>
                    <td className="py-2 text-right tabular-nums">{node.active_connections}</td>
                    <td className="py-2 text-right tabular-nums">{node.total_flows.toLocaleString()}</td>
                    <td className="py-2 text-right tabular-nums text-ink-400">v{node.policy_version}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>
    </>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between">
      <dt className="text-ink-400">{label}</dt>
      <dd className="tabular-nums text-ink-100">{value}</dd>
    </div>
  );
}

function ReadinessBanner({ status }: { status: PlatformStatus }) {
  const missingCA = status.ca === null;
  return (
    <Alert tone="warn">
      <p className="font-medium">Interception is not fully ready.</p>
      <ul className="mt-1 list-disc space-y-0.5 pl-5 text-xs">
        {missingCA && (
          <li>
            No active certificate authority.{" "}
            <Link href="/ca" className="underline">
              Generate one
            </Link>{" "}
            and install it on your clients.
          </li>
        )}
        {status.proxy_nodes.length === 0 && (
          <li>No proxy node has checked in within the last 45 seconds.</li>
        )}
        {status.ca && status.ca.expires_in_days < 30 && (
          <li>The active CA expires in {status.ca.expires_in_days} days.</li>
        )}
      </ul>
    </Alert>
  );
}

/** Subscribes to the flow WebSocket and keeps a rolling window of rows. */
function useLiveFlows(
  onFlow: React.Dispatch<React.SetStateAction<FlowSummary[]>>,
  onState: (state: "connecting" | "live" | "offline") => void,
) {
  const socketRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const url = flowStreamUrl();
    if (!url) return;

    let closed = false;
    let retry: ReturnType<typeof setTimeout>;

    const connect = () => {
      if (closed) return;
      onState("connecting");
      const socket = new WebSocket(url);
      socketRef.current = socket;

      socket.onopen = () => onState("live");
      socket.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          if (message.type === "flow") {
            onFlow((current) => [message.flow, ...current].slice(0, MAX_LIVE_ROWS));
          } else if (message.type === "warning") {
            onState("offline");
          }
        } catch {
          /* ignore malformed frames */
        }
      };
      socket.onclose = () => {
        if (closed) return;
        onState("offline");
        // The dashboard still polls every 10s, so a slow reconnect is harmless.
        retry = setTimeout(connect, 5_000);
      };
      socket.onerror = () => socket.close();
    };

    connect();
    return () => {
      closed = true;
      clearTimeout(retry);
      socketRef.current?.close();
    };
  }, [onFlow, onState]);
}
