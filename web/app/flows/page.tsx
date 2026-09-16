"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { PageHeader, Shell } from "@/components/shell";
import {
  ActionBadge,
  Alert,
  Button,
  Empty,
  Spinner,
  StatusBadge,
  formatBytes,
  formatTime,
} from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { FlowPage, FlowSummary } from "@/lib/types";

const PAGE_SIZE = 100;

interface Filters {
  host: string;
  search: string;
  method: string;
  status_code: string;
  action: string;
  client_ip: string;
  errors_only: boolean;
}

const EMPTY: Filters = {
  host: "",
  search: "",
  method: "",
  status_code: "",
  action: "",
  client_ip: "",
  errors_only: false,
};

export default function FlowsPage() {
  return (
    <Shell>
      <Flows />
    </Shell>
  );
}

function Flows() {
  const { can } = useAuth();
  const [filters, setFilters] = useState<Filters>(EMPTY);
  const [page, setPage] = useState<FlowPage | null>(null);
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const load = useCallback(async () => {
    const params = new URLSearchParams({
      limit: String(PAGE_SIZE),
      offset: String(offset),
    });
    if (filters.host) params.set("host", filters.host);
    if (filters.search) params.set("search", filters.search);
    if (filters.method) params.set("method", filters.method);
    if (filters.status_code) params.set("status_code", filters.status_code);
    if (filters.action) params.set("action", filters.action);
    if (filters.client_ip) params.set("client_ip", filters.client_ip);
    if (filters.errors_only) params.set("errors_only", "true");

    try {
      setPage(await api.listFlows(`?${params.toString()}`));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load traffic");
    } finally {
      setLoading(false);
    }
  }, [filters, offset]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!autoRefresh) return;
    const timer = setInterval(load, 5_000);
    return () => clearInterval(timer);
  }, [autoRefresh, load]);

  function update<K extends keyof Filters>(key: K, value: Filters[K]) {
    setOffset(0);
    setFilters((current) => ({ ...current, [key]: value }));
  }

  async function purge() {
    if (!confirm("Delete every recorded flow? Captured bodies age out separately.")) return;
    await api.purgeFlows();
    setOffset(0);
    load();
  }

  return (
    <>
      <PageHeader
        title="Traffic"
        description="Every transaction the proxy has seen. Decrypted requests show full method, path, headers and captured bodies."
      >
        <label className="flex items-center gap-2 text-xs text-ink-400">
          <input
            type="checkbox"
            checked={autoRefresh}
            onChange={(event) => setAutoRefresh(event.target.checked)}
          />
          Auto-refresh
        </label>
        {can("operator") && (
          <Button variant="danger" onClick={purge}>
            Clear history
          </Button>
        )}
      </PageHeader>

      <div className="space-y-4 p-8">
        <div className="card grid gap-3 p-4 md:grid-cols-3 xl:grid-cols-6">
          <input
            className="field"
            placeholder="Host contains…"
            value={filters.host}
            onChange={(event) => update("host", event.target.value)}
          />
          <input
            className="field"
            placeholder="Path contains…"
            value={filters.search}
            onChange={(event) => update("search", event.target.value)}
          />
          <select
            className="field"
            value={filters.method}
            onChange={(event) => update("method", event.target.value)}
          >
            <option value="">Any method</option>
            {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT"].map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
          <input
            className="field"
            placeholder="Status code"
            inputMode="numeric"
            value={filters.status_code}
            onChange={(event) => update("status_code", event.target.value.replace(/\D/g, ""))}
          />
          <select
            className="field"
            value={filters.action}
            onChange={(event) => update("action", event.target.value)}
          >
            <option value="">Any action</option>
            <option value="intercept">Intercepted</option>
            <option value="bypass">Tunnelled</option>
            <option value="block">Blocked</option>
          </select>
          <div className="flex items-center gap-3">
            <input
              className="field"
              placeholder="Client IP"
              value={filters.client_ip}
              onChange={(event) => update("client_ip", event.target.value)}
            />
            <label className="flex shrink-0 items-center gap-1.5 text-xs text-ink-400">
              <input
                type="checkbox"
                checked={filters.errors_only}
                onChange={(event) => update("errors_only", event.target.checked)}
              />
              Errors
            </label>
          </div>
        </div>

        {error && <Alert>{error}</Alert>}

        {loading && !page ? (
          <Spinner label="Loading traffic" />
        ) : !page || page.items.length === 0 ? (
          <div className="card">
            <Empty
              title="No flows match these filters"
              hint="Traffic appears once a client is configured to use the proxy and at least one request has completed."
            />
          </div>
        ) : (
          <>
            <div className="card overflow-hidden">
              <table className="w-full text-left text-sm">
                <thead className="bg-ink-900/60 text-xs uppercase tracking-wide text-ink-400">
                  <tr>
                    <th className="px-4 py-2.5">Time</th>
                    <th className="px-4 py-2.5">Status</th>
                    <th className="px-4 py-2.5">Method</th>
                    <th className="px-4 py-2.5">Host / path</th>
                    <th className="px-4 py-2.5">Client</th>
                    <th className="px-4 py-2.5 text-right">Size</th>
                    <th className="px-4 py-2.5 text-right">Time</th>
                    <th className="px-4 py-2.5 text-right">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {page.items.map((flow) => (
                    <FlowRow key={flow.id} flow={flow} />
                  ))}
                </tbody>
              </table>
            </div>

            <div className="flex items-center justify-between text-xs text-ink-400">
              <span>
                {offset + 1}–{Math.min(offset + page.items.length, page.total)} of{" "}
                {page.total.toLocaleString()}
              </span>
              <div className="flex gap-2">
                <Button
                  disabled={offset === 0}
                  onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
                >
                  Previous
                </Button>
                <Button
                  disabled={offset + PAGE_SIZE >= page.total}
                  onClick={() => setOffset(offset + PAGE_SIZE)}
                >
                  Next
                </Button>
              </div>
            </div>
          </>
        )}
      </div>
    </>
  );
}

function FlowRow({ flow }: { flow: FlowSummary }) {
  return (
    <tr className="border-t border-ink-800 transition hover:bg-ink-900/60">
      <td className="px-4 py-2 font-mono text-xs text-ink-400">{formatTime(flow.started_at)}</td>
      <td className="px-4 py-2">
        {flow.error ? <span className="text-xs text-bad">error</span> : <StatusBadge code={flow.status_code} />}
      </td>
      <td className="px-4 py-2 font-mono text-xs text-violet">{flow.method ?? "-"}</td>
      <td className="max-w-lg px-4 py-2">
        <Link href={`/flows/${flow.id}`} className="block truncate hover:text-accent">
          <span className="text-ink-100">{flow.host}</span>
          <span className="text-ink-400">{flow.path ?? ""}</span>
        </Link>
        {flow.error && <p className="truncate text-xs text-bad">{flow.error}</p>}
      </td>
      <td className="px-4 py-2 font-mono text-xs text-ink-400">{flow.client_ip}</td>
      <td className="px-4 py-2 text-right text-xs tabular-nums text-ink-400">
        {formatBytes(flow.request_size + flow.response_size)}
      </td>
      <td className="px-4 py-2 text-right text-xs tabular-nums text-ink-400">
        {flow.duration_ms === null ? "-" : `${flow.duration_ms} ms`}
      </td>
      <td className="px-4 py-2 text-right">
        <ActionBadge action={flow.action} />
      </td>
    </tr>
  );
}
