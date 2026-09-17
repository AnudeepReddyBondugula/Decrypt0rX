"use client";

import { useEffect } from "react";

export function Card({
  title,
  action,
  children,
  className = "",
}: {
  title?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={`card ${className}`}>
      {(title || action) && (
        <header className="flex items-center justify-between gap-3 border-b border-ink-700 px-5 py-3">
          {title && (
            <h2 className="text-sm font-semibold tracking-wide text-ink-200">{title}</h2>
          )}
          {action}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  );
}

type ButtonVariant = "primary" | "ghost" | "danger" | "subtle";

const BUTTON_STYLES: Record<ButtonVariant, string> = {
  primary: "bg-accent-dim text-ink-950 hover:bg-accent font-semibold",
  ghost: "border border-ink-600 text-ink-200 hover:border-ink-400 hover:text-white",
  danger: "border border-bad/40 text-bad hover:bg-bad/10",
  subtle: "text-ink-300 hover:text-white",
};

export function Button({
  variant = "ghost",
  className = "",
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  return (
    <button
      {...props}
      className={`inline-flex items-center justify-center gap-2 rounded-lg px-3 py-1.5 text-sm transition disabled:cursor-not-allowed disabled:opacity-50 ${BUTTON_STYLES[variant]} ${className}`}
    />
  );
}

export function Badge({
  tone = "neutral",
  children,
}: {
  tone?: "neutral" | "good" | "warn" | "bad" | "info" | "violet";
  children: React.ReactNode;
}) {
  const tones = {
    neutral: "bg-ink-700/60 text-ink-200 border-ink-600",
    good: "bg-good/10 text-good border-good/30",
    warn: "bg-warn/10 text-warn border-warn/30",
    bad: "bg-bad/10 text-bad border-bad/30",
    info: "bg-accent/10 text-accent border-accent/30",
    violet: "bg-violet/10 text-violet border-violet/30",
  } as const;
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide ${tones[tone]}`}
    >
      {children}
    </span>
  );
}

export function ActionBadge({ action }: { action: string }) {
  const tone = action === "block" ? "bad" : action === "bypass" ? "warn" : "info";
  return <Badge tone={tone}>{action}</Badge>;
}

export function StatusBadge({ code }: { code: number | null }) {
  if (code === null) return <span className="text-ink-400">-</span>;
  const tone =
    code >= 500 ? "bad" : code >= 400 ? "warn" : code >= 300 ? "violet" : "good";
  return <Badge tone={tone}>{code}</Badge>;
}

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block space-y-1.5">
      <span className="text-xs font-medium uppercase tracking-wide text-ink-300">
        {label}
      </span>
      {children}
      {hint && <span className="block text-xs text-ink-400">{hint}</span>}
    </label>
  );
}

export function Alert({
  tone = "bad",
  children,
}: {
  tone?: "bad" | "good" | "warn" | "info";
  children: React.ReactNode;
}) {
  const tones = {
    bad: "border-bad/40 bg-bad/10 text-bad",
    good: "border-good/40 bg-good/10 text-good",
    warn: "border-warn/40 bg-warn/10 text-warn",
    info: "border-accent/40 bg-accent/10 text-accent",
  } as const;
  return (
    <div className={`rounded-lg border px-4 py-3 text-sm ${tones[tone]}`}>{children}</div>
  );
}

export function Modal({
  title,
  onClose,
  children,
  wide = false,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  wide?: boolean;
}) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/70 p-6 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className={`card my-8 w-full ${wide ? "max-w-3xl" : "max-w-xl"} shadow-2xl`}
        onClick={(event) => event.stopPropagation()}
      >
        <header className="flex items-center justify-between border-b border-ink-700 px-5 py-3">
          <h2 className="text-sm font-semibold text-ink-100">{title}</h2>
          <Button variant="subtle" onClick={onClose} aria-label="Close">
            ✕
          </Button>
        </header>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}

export function Empty({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-14 text-center">
      <p className="text-sm text-ink-300">{title}</p>
      {hint && <p className="max-w-md text-xs text-ink-400">{hint}</p>}
    </div>
  );
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-3 py-12 text-sm text-ink-400">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-ink-600 border-t-accent" />
      {label}
    </div>
  );
}

export function Stat({
  label,
  value,
  sub,
  tone = "neutral",
}: {
  label: string;
  value: string | number;
  sub?: string;
  tone?: "neutral" | "good" | "warn" | "bad" | "info";
}) {
  const colors = {
    neutral: "text-ink-100",
    good: "text-good",
    warn: "text-warn",
    bad: "text-bad",
    info: "text-accent",
  } as const;
  return (
    <div className="card p-4">
      <p className="text-xs uppercase tracking-wide text-ink-400">{label}</p>
      <p className={`mt-1 text-2xl font-semibold tabular-nums ${colors[tone]}`}>{value}</p>
      {sub && <p className="mt-0.5 text-xs text-ink-400">{sub}</p>}
    </div>
  );
}

export function formatBytes(bytes: number): string {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** index;
  return `${value < 10 && index > 0 ? value.toFixed(1) : Math.round(value)} ${units[index]}`;
}

export function formatTime(iso: string): string {
  return new Date(iso).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString();
}

export function relativeTime(iso: string): string {
  const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}
