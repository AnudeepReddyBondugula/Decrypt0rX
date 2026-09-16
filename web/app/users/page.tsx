"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader, Shell } from "@/components/shell";
import {
  Alert,
  Badge,
  Button,
  Field,
  Modal,
  Spinner,
  formatDateTime,
  relativeTime,
} from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { Role, User } from "@/lib/types";

const ROLE_HINTS: Record<Role, string> = {
  admin: "Full control, including certificates and users.",
  operator: "Can change policy and clear traffic history.",
  viewer: "Read-only access to captured traffic.",
};

export default function UsersPage() {
  return (
    <Shell>
      <Users />
    </Shell>
  );
}

function Users() {
  const { user: me } = useAuth();
  const [users, setUsers] = useState<User[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const load = useCallback(async () => {
    try {
      setUsers(await api.listUsers());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load users");
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function changeRole(user: User, role: Role) {
    try {
      await api.updateUser(user.id, { role });
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not update the user");
    }
  }

  async function toggleActive(user: User) {
    try {
      await api.updateUser(user.id, { is_active: !user.is_active });
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not update the user");
    }
  }

  async function remove(user: User) {
    if (!confirm(`Delete ${user.email}?`)) return;
    try {
      await api.deleteUser(user.id);
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not delete the user");
    }
  }

  return (
    <>
      <PageHeader
        title="Users"
        description="Anyone with access here can read decrypted traffic. Grant the lowest role that does the job."
      >
        <Button variant="primary" onClick={() => setCreating(true)}>
          + New user
        </Button>
      </PageHeader>

      <div className="space-y-4 p-8">
        {error && <Alert>{error}</Alert>}
        {!users ? (
          <Spinner label="Loading users" />
        ) : (
          <div className="card overflow-hidden">
            <table className="w-full text-left text-sm">
              <thead className="bg-ink-900/60 text-xs uppercase tracking-wide text-ink-400">
                <tr>
                  <th className="px-4 py-2.5">User</th>
                  <th className="px-4 py-2.5">Role</th>
                  <th className="px-4 py-2.5">Status</th>
                  <th className="px-4 py-2.5">Last login</th>
                  <th className="px-4 py-2.5 text-right">Manage</th>
                </tr>
              </thead>
              <tbody>
                {users.map((user) => (
                  <tr key={user.id} className="border-t border-ink-800">
                    <td className="px-4 py-3">
                      <p className="text-ink-100">{user.email}</p>
                      {user.full_name && <p className="text-xs text-ink-400">{user.full_name}</p>}
                      <p className="text-xs text-ink-500">
                        added {formatDateTime(user.created_at)}
                      </p>
                    </td>
                    <td className="px-4 py-3">
                      <select
                        className="field w-32"
                        value={user.role}
                        onChange={(event) => changeRole(user, event.target.value as Role)}
                      >
                        <option value="viewer">viewer</option>
                        <option value="operator">operator</option>
                        <option value="admin">admin</option>
                      </select>
                      <p className="mt-1 max-w-48 text-[11px] text-ink-500">
                        {ROLE_HINTS[user.role]}
                      </p>
                    </td>
                    <td className="px-4 py-3">
                      {user.is_active ? <Badge tone="good">active</Badge> : <Badge tone="bad">disabled</Badge>}
                      {me?.id === user.id && (
                        <span className="ml-2 text-xs text-ink-400">(you)</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-ink-400">
                      {user.last_login_at ? relativeTime(user.last_login_at) : "never"}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end gap-2">
                        <Button onClick={() => toggleActive(user)} disabled={me?.id === user.id}>
                          {user.is_active ? "Disable" : "Enable"}
                        </Button>
                        <Button
                          variant="danger"
                          onClick={() => remove(user)}
                          disabled={me?.id === user.id}
                        >
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
        <ChangeOwnPassword />
      </div>

      {creating && (
        <CreateUser
          onClose={() => setCreating(false)}
          onDone={() => {
            setCreating(false);
            load();
          }}
        />
      )}
    </>
  );
}

function CreateUser({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [form, setForm] = useState({
    email: "",
    full_name: "",
    password: "",
    role: "viewer" as Role,
  });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.createUser({ ...form, full_name: form.full_name || null });
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create the user");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title="New user" onClose={onClose}>
      <form onSubmit={submit} className="space-y-4">
        {error && <Alert>{error}</Alert>}
        <Field label="Email">
          <input
            className="field"
            type="email"
            required
            value={form.email}
            onChange={(event) => setForm({ ...form, email: event.target.value })}
          />
        </Field>
        <Field label="Full name">
          <input
            className="field"
            value={form.full_name}
            onChange={(event) => setForm({ ...form, full_name: event.target.value })}
          />
        </Field>
        <Field label="Password" hint="At least 12 characters.">
          <input
            className="field"
            type="password"
            required
            minLength={12}
            value={form.password}
            onChange={(event) => setForm({ ...form, password: event.target.value })}
          />
        </Field>
        <Field label="Role" hint={ROLE_HINTS[form.role]}>
          <select
            className="field"
            value={form.role}
            onChange={(event) => setForm({ ...form, role: event.target.value as Role })}
          >
            <option value="viewer">viewer</option>
            <option value="operator">operator</option>
            <option value="admin">admin</option>
          </select>
        </Field>
        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" disabled={busy}>
            {busy ? "Creating…" : "Create user"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function ChangeOwnPassword() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [message, setMessage] = useState<{ tone: "good" | "bad"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      await api.changePassword(current, next);
      setMessage({ tone: "good", text: "Password updated." });
      setCurrent("");
      setNext("");
    } catch (err) {
      setMessage({
        tone: "bad",
        text: err instanceof Error ? err.message : "Could not change the password",
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card p-5">
      <h2 className="text-sm font-semibold text-ink-200">Change your password</h2>
      <form onSubmit={submit} className="mt-3 flex flex-wrap items-end gap-3">
        <div className="min-w-52">
          <Field label="Current password">
            <input
              className="field"
              type="password"
              required
              value={current}
              onChange={(event) => setCurrent(event.target.value)}
            />
          </Field>
        </div>
        <div className="min-w-52">
          <Field label="New password">
            <input
              className="field"
              type="password"
              required
              minLength={12}
              value={next}
              onChange={(event) => setNext(event.target.value)}
            />
          </Field>
        </div>
        <Button type="submit" variant="primary" disabled={busy}>
          Update
        </Button>
      </form>
      {message && (
        <div className="mt-3">
          <Alert tone={message.tone}>{message.text}</Alert>
        </div>
      )}
    </div>
  );
}
