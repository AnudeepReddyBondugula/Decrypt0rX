"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { Alert, Button, Field } from "@/components/ui";

export default function LoginPage() {
  const { signIn, user, loading } = useAuth();
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!loading && user) router.replace("/");
  }, [loading, user, router]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await signIn(email.trim(), password);
      router.replace("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign-in failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-6">
      <div className="w-full max-w-sm">
        <div className="mb-8 text-center">
          <p className="font-mono text-3xl font-bold tracking-tight">
            Decrypt<span className="text-accent">0rX</span>
          </p>
          <p className="mt-2 text-sm text-ink-400">
            Sign in to manage interception, policy and traffic.
          </p>
        </div>

        <form onSubmit={submit} className="card space-y-4 p-6">
          {error && <Alert>{error}</Alert>}
          <Field label="Email">
            <input
              className="field"
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="admin@decrypt0rx.io"
            />
          </Field>
          <Field label="Password">
            <input
              className="field"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </Field>
          <Button type="submit" variant="primary" className="w-full" disabled={busy}>
            {busy ? "Signing in…" : "Sign in"}
          </Button>
        </form>

        <p className="mt-6 text-center text-xs text-ink-400">
          The bootstrap password is printed once in the API container logs on first
          start.
        </p>
      </div>
    </div>
  );
}
