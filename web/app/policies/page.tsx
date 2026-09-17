"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader, Shell } from "@/components/shell";
import {
  ActionBadge,
  Alert,
  Badge,
  Button,
  Card,
  Empty,
  Field,
  Modal,
  Spinner,
} from "@/components/ui";
import { api } from "@/lib/api";
import type { PolicyAction, PolicyRule, PolicyVerdict } from "@/lib/types";

interface Draft {
  name: string;
  description: string;
  priority: number;
  enabled: boolean;
  host_pattern: string;
  client_cidr: string;
  port: string;
  action: PolicyAction;
  capture_bodies: boolean;
  capture_max_bytes: number;
  redact: boolean;
}

const BLANK: Draft = {
  name: "",
  description: "",
  priority: 100,
  enabled: true,
  host_pattern: "*.example.com",
  client_cidr: "",
  port: "",
  action: "intercept",
  capture_bodies: false,
  capture_max_bytes: 1_048_576,
  redact: true,
};

export default function PoliciesPage() {
  return (
    <Shell>
      <Policies />
    </Shell>
  );
}

function Policies() {
  const [rules, setRules] = useState<PolicyRule[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<PolicyRule | "new" | null>(null);

  const load = useCallback(async () => {
    try {
      setRules(await api.listPolicies());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load policies");
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function toggle(rule: PolicyRule) {
    await api.updatePolicy(rule.id, { enabled: !rule.enabled });
    load();
  }

  async function remove(rule: PolicyRule) {
    if (!confirm(`Delete the rule "${rule.name}"?`)) return;
    await api.deletePolicy(rule.id);
    load();
  }

  return (
    <>
      <PageHeader
        title="Access policies"
        description="Evaluated top to bottom by priority. The first rule that matches a connection decides what happens to it."
      >
        <Button variant="primary" onClick={() => setEditing("new")}>
          + New rule
        </Button>
      </PageHeader>

      <div className="space-y-6 p-8">
        {error && <Alert>{error}</Alert>}
        <PolicyTester />

        {!rules ? (
          <Spinner label="Loading policies" />
        ) : rules.length === 0 ? (
          <div className="card">
            <Empty title="No rules yet" hint="Without rules, every connection is intercepted with metadata-only capture." />
          </div>
        ) : (
          <div className="card overflow-hidden">
            <table className="w-full text-left text-sm">
              <thead className="bg-ink-900/60 text-xs uppercase tracking-wide text-ink-400">
                <tr>
                  <th className="px-4 py-2.5 w-16">Priority</th>
                  <th className="px-4 py-2.5">Rule</th>
                  <th className="px-4 py-2.5">Matches</th>
                  <th className="px-4 py-2.5">Action</th>
                  <th className="px-4 py-2.5">Capture</th>
                  <th className="px-4 py-2.5 text-right">Manage</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr
                    key={rule.id}
                    className={`border-t border-ink-800 ${rule.enabled ? "" : "opacity-45"}`}
                  >
                    <td className="px-4 py-3 font-mono text-xs tabular-nums text-ink-400">
                      {rule.priority}
                    </td>
                    <td className="px-4 py-3">
                      <p className="font-medium text-ink-100">{rule.name}</p>
                      {rule.description && (
                        <p className="max-w-lg text-xs text-ink-400">{rule.description}</p>
                      )}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-ink-300">
                      <div>{rule.host_pattern}</div>
                      {rule.client_cidr && <div className="text-ink-400">from {rule.client_cidr}</div>}
                      {rule.port && <div className="text-ink-400">port {rule.port}</div>}
                    </td>
                    <td className="px-4 py-3">
                      <ActionBadge action={rule.action} />
                    </td>
                    <td className="px-4 py-3">
                      {rule.action !== "intercept" ? (
                        <span className="text-xs text-ink-500">n/a</span>
                      ) : rule.capture_bodies ? (
                        <div className="flex flex-wrap gap-1">
                          <Badge tone="good">bodies</Badge>
                          {rule.redact && <Badge tone="warn">redacted</Badge>}
                        </div>
                      ) : (
                        <Badge>metadata</Badge>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end gap-2">
                        <Button onClick={() => toggle(rule)}>
                          {rule.enabled ? "Disable" : "Enable"}
                        </Button>
                        <Button onClick={() => setEditing(rule)}>Edit</Button>
                        <Button variant="danger" onClick={() => remove(rule)}>
                          Delete
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {editing && (
        <RuleEditor
          rule={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            load();
          }}
        />
      )}
    </>
  );
}

function PolicyTester() {
  const [host, setHost] = useState("");
  const [clientIp, setClientIp] = useState("");
  const [verdict, setVerdict] = useState<PolicyVerdict | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run(event: React.FormEvent) {
    event.preventDefault();
    try {
      setVerdict(
        await api.testPolicy({
          host: host.trim(),
          client_ip: clientIp.trim() || undefined,
        }),
      );
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Test failed");
    }
  }

  return (
    <Card title="What would happen to…">
      <form onSubmit={run} className="flex flex-wrap items-end gap-3">
        <div className="min-w-56 flex-1">
          <Field label="Host">
            <input
              className="field"
              required
              placeholder="api.example.com"
              value={host}
              onChange={(event) => setHost(event.target.value)}
            />
          </Field>
        </div>
        <div className="min-w-44">
          <Field label="Client IP (optional)">
            <input
              className="field"
              placeholder="10.0.0.5"
              value={clientIp}
              onChange={(event) => setClientIp(event.target.value)}
            />
          </Field>
        </div>
        <Button type="submit" variant="primary">
          Evaluate
        </Button>
      </form>

      {error && <div className="mt-3"><Alert>{error}</Alert></div>}
      {verdict && (
        <div className="mt-4 flex flex-wrap items-center gap-3 rounded-lg border border-ink-700 bg-ink-950 px-4 py-3 text-sm">
          <ActionBadge action={verdict.action} />
          <span className="text-ink-300">
            matched{" "}
            <span className="font-medium text-ink-100">
              {verdict.matched_rule_name ?? "no rule (built-in default)"}
            </span>
          </span>
          <Badge tone={verdict.capture_bodies ? "good" : "neutral"}>
            {verdict.capture_bodies ? "bodies captured" : "metadata only"}
          </Badge>
          {verdict.redact && <Badge tone="warn">redacted</Badge>}
        </div>
      )}
    </Card>
  );
}

function RuleEditor({
  rule,
  onClose,
  onSaved,
}: {
  rule: PolicyRule | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [draft, setDraft] = useState<Draft>(
    rule
      ? {
          name: rule.name,
          description: rule.description ?? "",
          priority: rule.priority,
          enabled: rule.enabled,
          host_pattern: rule.host_pattern,
          client_cidr: rule.client_cidr ?? "",
          port: rule.port ? String(rule.port) : "",
          action: rule.action,
          capture_bodies: rule.capture_bodies,
          capture_max_bytes: rule.capture_max_bytes,
          redact: rule.redact,
        }
      : BLANK,
  );
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function set<K extends keyof Draft>(key: K, value: Draft[K]) {
    setDraft((current) => ({ ...current, [key]: value }));
  }

  async function save(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    const payload = {
      ...draft,
      description: draft.description || null,
      client_cidr: draft.client_cidr || null,
      port: draft.port ? Number(draft.port) : null,
    };
    try {
      if (rule) await api.updatePolicy(rule.id, payload);
      else await api.createPolicy(payload);
      onSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save the rule");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title={rule ? `Edit "${rule.name}"` : "New policy rule"} onClose={onClose} wide>
      <form onSubmit={save} className="space-y-4">
        {error && <Alert>{error}</Alert>}

        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Name">
            <input
              className="field"
              required
              value={draft.name}
              onChange={(event) => set("name", event.target.value)}
            />
          </Field>
          <Field label="Priority" hint="Lower numbers are evaluated first.">
            <input
              className="field"
              type="number"
              min={0}
              value={draft.priority}
              onChange={(event) => set("priority", Number(event.target.value))}
            />
          </Field>
        </div>

        <Field label="Description">
          <input
            className="field"
            value={draft.description}
            onChange={(event) => set("description", event.target.value)}
            placeholder="Why this rule exists"
          />
        </Field>

        <div className="grid gap-4 sm:grid-cols-3">
          <Field label="Host pattern" hint="Glob, e.g. *.internal.corp">
            <input
              className="field"
              required
              value={draft.host_pattern}
              onChange={(event) => set("host_pattern", event.target.value)}
            />
          </Field>
          <Field label="Client CIDR" hint="Optional source restriction">
            <input
              className="field"
              value={draft.client_cidr}
              onChange={(event) => set("client_cidr", event.target.value)}
              placeholder="10.0.0.0/8"
            />
          </Field>
          <Field label="Port" hint="Optional; blank matches any">
            <input
              className="field"
              inputMode="numeric"
              value={draft.port}
              onChange={(event) => set("port", event.target.value.replace(/\D/g, ""))}
              placeholder="443"
            />
          </Field>
        </div>

        <Field label="Action">
          <div className="grid gap-2 sm:grid-cols-3">
            {(
              [
                ["intercept", "Decrypt and log the traffic."],
                ["bypass", "Tunnel untouched. Use for pinned apps."],
                ["block", "Refuse the connection with 403."],
              ] as const
            ).map(([value, hint]) => (
              <button
                key={value}
                type="button"
                onClick={() => set("action", value)}
                className={`rounded-lg border p-3 text-left text-sm transition ${
                  draft.action === value
                    ? "border-accent bg-accent/10 text-accent"
                    : "border-ink-700 text-ink-300 hover:border-ink-600"
                }`}
              >
                <span className="block font-medium capitalize">{value}</span>
                <span className="mt-0.5 block text-xs text-ink-400">{hint}</span>
              </button>
            ))}
          </div>
        </Field>

        {draft.action === "intercept" && (
          <div className="space-y-3 rounded-lg border border-ink-700 bg-ink-950/60 p-4">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={draft.capture_bodies}
                onChange={(event) => set("capture_bodies", event.target.checked)}
              />
              Capture request and response bodies
            </label>
            {draft.capture_bodies && (
              <>
                <Field label="Capture limit (bytes)" hint="Larger bodies are forwarded in full but stored truncated.">
                  <input
                    className="field"
                    type="number"
                    min={0}
                    value={draft.capture_max_bytes}
                    onChange={(event) => set("capture_max_bytes", Number(event.target.value))}
                  />
                </Field>
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={draft.redact}
                    onChange={(event) => set("redact", event.target.checked)}
                  />
                  Redact credentials before storing
                </label>
                {!draft.redact && (
                  <Alert tone="warn">
                    With redaction off, Authorization headers, cookies and password fields
                    are stored in clear text and shown to anyone who can read traffic.
                  </Alert>
                )}
              </>
            )}
          </div>
        )}

        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={draft.enabled}
            onChange={(event) => set("enabled", event.target.checked)}
          />
          Rule enabled
        </label>

        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" disabled={busy}>
            {busy ? "Saving…" : rule ? "Save changes" : "Create rule"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
