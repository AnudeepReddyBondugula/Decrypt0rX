"use client";

import { useEffect, useState } from "react";
import { PageHeader, Shell } from "@/components/shell";
import { Alert, Badge, Empty, Spinner, formatDateTime } from "@/components/ui";
import { api } from "@/lib/api";
import type { AuditEntry } from "@/lib/types";

export default function AuditPage() {
  return (
    <Shell>
      <AuditLog />
    </Shell>
  );
}

function tone(action: string) {
  if (action.includes("deleted") || action.includes("failed")) return "bad";
  if (action.startsWith("ca.")) return "violet";
  if (action.startsWith("policy.")) return "info";
  return "neutral";
}

function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .audit(200)
      .then(setEntries)
      .catch((err) => setError(err instanceof Error ? err.message : "Could not load"));
  }, []);

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Every control-plane change: who did it, when, and from where."
      />
      <div className="p-8">
        {error && <Alert>{error}</Alert>}
        {!entries ? (
          <Spinner label="Loading audit log" />
        ) : entries.length === 0 ? (
          <div className="card">
            <Empty title="Nothing recorded yet" />
          </div>
        ) : (
          <div className="card overflow-hidden">
            <table className="w-full text-left text-sm">
              <thead className="bg-ink-900/60 text-xs uppercase tracking-wide text-ink-400">
                <tr>
                  <th className="px-4 py-2.5">When</th>
                  <th className="px-4 py-2.5">Actor</th>
                  <th className="px-4 py-2.5">Action</th>
                  <th className="px-4 py-2.5">Target</th>
                  <th className="px-4 py-2.5">Detail</th>
                  <th className="px-4 py-2.5">Source IP</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => (
                  <tr key={entry.id} className="border-t border-ink-800">
                    <td className="whitespace-nowrap px-4 py-2 text-xs text-ink-400">
                      {formatDateTime(entry.created_at)}
                    </td>
                    <td className="px-4 py-2 text-xs text-ink-200">{entry.actor}</td>
                    <td className="px-4 py-2">
                      <Badge tone={tone(entry.action)}>{entry.action}</Badge>
                    </td>
                    <td className="px-4 py-2 font-mono text-xs text-ink-300">
                      {entry.target ?? "-"}
                    </td>
                    <td className="max-w-md truncate px-4 py-2 font-mono text-[11px] text-ink-400">
                      {entry.detail ? JSON.stringify(entry.detail) : "-"}
                    </td>
                    <td className="px-4 py-2 font-mono text-xs text-ink-400">
                      {entry.client_ip ?? "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}
