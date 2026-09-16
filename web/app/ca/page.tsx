"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader, Shell } from "@/components/shell";
import {
  Alert,
  Badge,
  Button,
  Card,
  Empty,
  Field,
  Modal,
  Spinner,
  formatDateTime,
} from "@/components/ui";
import { api } from "@/lib/api";
import type { CertificateAuthority } from "@/lib/types";

export default function CAPage() {
  return (
    <Shell>
      <CertificateAuthorities />
    </Shell>
  );
}

function CertificateAuthorities() {
  const [cas, setCAs] = useState<CertificateAuthority[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dialog, setDialog] = useState<"generate" | "import" | null>(null);

  const load = useCallback(async () => {
    try {
      setCAs(await api.listCAs());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load certificates");
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const active = cas?.find((ca) => ca.is_active) ?? null;

  async function activate(ca: CertificateAuthority) {
    if (
      !confirm(
        `Make "${ca.name}" the signing CA?\n\nClients that only trust the previous CA will start seeing certificate errors until they install this one.`,
      )
    )
      return;
    await api.activateCA(ca.id);
    load();
  }

  async function remove(ca: CertificateAuthority) {
    if (!confirm(`Delete "${ca.name}"? This cannot be undone.`)) return;
    try {
      await api.deleteCA(ca.id);
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not delete");
    }
  }

  return (
    <>
      <PageHeader
        title="Certificate authorities"
        description="The proxy forges a certificate per host from the active CA. Clients must trust that CA or every intercepted connection fails."
      >
        <Button onClick={() => setDialog("import")}>Import existing</Button>
        <Button variant="primary" onClick={() => setDialog("generate")}>
          + Generate CA
        </Button>
      </PageHeader>

      <div className="space-y-6 p-8">
        {error && <Alert>{error}</Alert>}
        {cas && !active && (
          <Alert tone="warn">
            No CA is active, so interception cannot work. Generate one and install it on
            your clients.
          </Alert>
        )}
        {active && <InstallGuide ca={active} />}

        {!cas ? (
          <Spinner label="Loading certificates" />
        ) : cas.length === 0 ? (
          <div className="card">
            <Empty
              title="No certificate authority yet"
              hint="Generate a root CA to start intercepting. The private key is encrypted before it is stored and is never served by the API."
            />
          </div>
        ) : (
          <div className="grid gap-4 xl:grid-cols-2">
            {cas.map((ca) => (
              <CACard key={ca.id} ca={ca} onActivate={activate} onDelete={remove} />
            ))}
          </div>
        )}
      </div>

      {dialog === "generate" && (
        <GenerateDialog onClose={() => setDialog(null)} onDone={() => { setDialog(null); load(); }} />
      )}
      {dialog === "import" && (
        <ImportDialog onClose={() => setDialog(null)} onDone={() => { setDialog(null); load(); }} />
      )}
    </>
  );
}

function CACard({
  ca,
  onActivate,
  onDelete,
}: {
  ca: CertificateAuthority;
  onActivate: (ca: CertificateAuthority) => void;
  onDelete: (ca: CertificateAuthority) => void;
}) {
  const daysLeft = Math.round(
    (new Date(ca.not_after).getTime() - Date.now()) / 86_400_000,
  );
  const expired = daysLeft <= 0;

  return (
    <Card
      title={ca.name}
      action={
        <div className="flex gap-2">
          {ca.is_active ? <Badge tone="good">active</Badge> : <Badge>standby</Badge>}
          <Badge tone={ca.source === "imported" ? "violet" : "neutral"}>{ca.source}</Badge>
        </div>
      }
    >
      <dl className="space-y-2 text-sm">
        <div>
          <dt className="text-xs uppercase tracking-wide text-ink-400">Subject</dt>
          <dd className="break-all font-mono text-xs text-ink-200">{ca.subject}</dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-ink-400">SHA-256 fingerprint</dt>
          <dd className="break-all font-mono text-[11px] text-ink-300">
            {ca.fingerprint_sha256}
          </dd>
        </div>
        <div className="flex gap-6">
          <div>
            <dt className="text-xs uppercase tracking-wide text-ink-400">Key</dt>
            <dd className="text-xs text-ink-200">{ca.key_algorithm}</dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-ink-400">Expires</dt>
            <dd className={`text-xs ${expired ? "text-bad" : daysLeft < 30 ? "text-warn" : "text-ink-200"}`}>
              {formatDateTime(ca.not_after)} ({expired ? "expired" : `${daysLeft} days`})
            </dd>
          </div>
        </div>
      </dl>

      <div className="mt-4 flex flex-wrap gap-2">
        <a href={api.caDownloadUrl(ca.id)} target="_blank" rel="noreferrer">
          <Button>Download .crt</Button>
        </a>
        {!ca.is_active && !expired && <Button onClick={() => onActivate(ca)}>Make active</Button>}
        {!ca.is_active && (
          <Button variant="danger" onClick={() => onDelete(ca)}>
            Delete
          </Button>
        )}
      </div>
    </Card>
  );
}

function InstallGuide({ ca }: { ca: CertificateAuthority }) {
  const url = api.publicRootUrl();
  return (
    <Card title="Install this CA on your clients">
      <p className="text-sm text-ink-300">
        Until a client trusts <span className="font-mono text-ink-100">{ca.name}</span>, every
        intercepted HTTPS request fails with a certificate error. The download below needs no
        login, so you can fetch it from the client itself.
      </p>
      <div className="mt-3 rounded-lg bg-ink-950 p-3 font-mono text-xs text-ink-300">
        curl -fsSL {url} -o decrypt0rx-root.crt
      </div>
      <div className="mt-4 grid gap-4 text-xs text-ink-300 md:grid-cols-2 xl:grid-cols-4">
        <Platform title="Linux (Debian/Ubuntu)">
          sudo cp decrypt0rx-root.crt /usr/local/share/ca-certificates/{"\n"}
          sudo update-ca-certificates
        </Platform>
        <Platform title="macOS">
          sudo security add-trusted-cert -d -r trustRoot{"\n"}
          {"  "}-k /Library/Keychains/System.keychain decrypt0rx-root.crt
        </Platform>
        <Platform title="Windows (admin shell)">
          certutil -addstore -f Root decrypt0rx-root.crt
        </Platform>
        <Platform title="Then point the client at the proxy">
          export HTTPS_PROXY=http://&lt;proxy-host&gt;:8080{"\n"}
          export HTTP_PROXY=http://&lt;proxy-host&gt;:8080
        </Platform>
      </div>
      <Alert tone="warn">
        Installing a CA lets whoever holds its private key read that client&apos;s HTTPS
        traffic. Only do this on devices you are authorised to monitor.
      </Alert>
    </Card>
  );
}

function Platform({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="mb-1 font-medium text-ink-200">{title}</p>
      <pre className="overflow-x-auto rounded-lg bg-ink-950 p-3 font-mono text-[11px] leading-relaxed text-ink-300">
        {children}
      </pre>
    </div>
  );
}

function GenerateDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [form, setForm] = useState({
    name: "Primary CA",
    common_name: "Decrypt0rX Root CA",
    organization: "Decrypt0rX",
    valid_days: 3650,
    key_algorithm: "rsa-2048",
    activate: true,
  });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.generateCA(form);
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not generate the CA");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title="Generate a root CA" onClose={onClose}>
      <form onSubmit={submit} className="space-y-4">
        {error && <Alert>{error}</Alert>}
        <Field label="Display name" hint="How this CA appears in Decrypt0rX.">
          <input
            className="field"
            required
            value={form.name}
            onChange={(event) => setForm({ ...form, name: event.target.value })}
          />
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Common name" hint="Shown in the client's trust store.">
            <input
              className="field"
              required
              maxLength={64}
              value={form.common_name}
              onChange={(event) => setForm({ ...form, common_name: event.target.value })}
            />
          </Field>
          <Field label="Organization">
            <input
              className="field"
              value={form.organization}
              onChange={(event) => setForm({ ...form, organization: event.target.value })}
            />
          </Field>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Valid for (days)">
            <input
              className="field"
              type="number"
              min={1}
              max={7300}
              value={form.valid_days}
              onChange={(event) => setForm({ ...form, valid_days: Number(event.target.value) })}
            />
          </Field>
          <Field label="Key algorithm" hint="RSA-2048 is the most widely accepted.">
            <select
              className="field"
              value={form.key_algorithm}
              onChange={(event) => setForm({ ...form, key_algorithm: event.target.value })}
            >
              <option value="rsa-2048">RSA 2048</option>
              <option value="rsa-4096">RSA 4096</option>
              <option value="ecdsa-p256">ECDSA P-256</option>
            </select>
          </Field>
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={form.activate}
            onChange={(event) => setForm({ ...form, activate: event.target.checked })}
          />
          Make this the active signing CA
        </label>
        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" disabled={busy}>
            {busy ? "Generating…" : "Generate"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function ImportDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [form, setForm] = useState({
    name: "",
    cert_pem: "",
    key_pem: "",
    passphrase: "",
    activate: false,
  });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.importCA({ ...form, passphrase: form.passphrase || null });
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not import the CA");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title="Import an existing CA" onClose={onClose} wide>
      <form onSubmit={submit} className="space-y-4">
        {error && <Alert>{error}</Alert>}
        <p className="text-sm text-ink-400">
          Paste a CA certificate and its private key. The key is encrypted with the
          deployment master key before it is stored, and is never returned by the API.
        </p>
        <Field label="Display name">
          <input
            className="field"
            required
            value={form.name}
            onChange={(event) => setForm({ ...form, name: event.target.value })}
          />
        </Field>
        <Field label="Certificate (PEM)">
          <textarea
            className="field h-32 font-mono text-xs"
            required
            placeholder="-----BEGIN CERTIFICATE-----"
            value={form.cert_pem}
            onChange={(event) => setForm({ ...form, cert_pem: event.target.value })}
          />
        </Field>
        <Field label="Private key (PEM)">
          <textarea
            className="field h-32 font-mono text-xs"
            required
            placeholder="-----BEGIN PRIVATE KEY-----"
            value={form.key_pem}
            onChange={(event) => setForm({ ...form, key_pem: event.target.value })}
          />
        </Field>
        <Field label="Key passphrase" hint="Leave blank if the key is not encrypted.">
          <input
            className="field"
            type="password"
            value={form.passphrase}
            onChange={(event) => setForm({ ...form, passphrase: event.target.value })}
          />
        </Field>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={form.activate}
            onChange={(event) => setForm({ ...form, activate: event.target.checked })}
          />
          Make this the active signing CA
        </label>
        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" disabled={busy}>
            {busy ? "Importing…" : "Import"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
