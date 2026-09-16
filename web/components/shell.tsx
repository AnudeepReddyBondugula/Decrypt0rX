"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect } from "react";
import { useAuth } from "@/lib/auth";
import type { Role } from "@/lib/types";
import { Spinner } from "./ui";

const NAV: { href: string; label: string; icon: string; minimum: Role }[] = [
  { href: "/", label: "Dashboard", icon: "◉", minimum: "viewer" },
  { href: "/flows", label: "Traffic", icon: "⇄", minimum: "viewer" },
  { href: "/policies", label: "Policies", icon: "⛨", minimum: "operator" },
  { href: "/ca", label: "Certificates", icon: "🔑", minimum: "admin" },
  { href: "/users", label: "Users", icon: "👤", minimum: "admin" },
  { href: "/audit", label: "Audit log", icon: "🗒", minimum: "admin" },
];

/** Wraps every authenticated page: redirects anonymous visitors to /login and
 *  hides nav entries the current role cannot use. */
export function Shell({ children }: { children: React.ReactNode }) {
  const { user, loading, signOut, can } = useAuth();
  const pathname = usePathname();
  const router = useRouter();

  useEffect(() => {
    if (!loading && !user) router.replace("/login");
  }, [loading, user, router]);

  if (loading) return <Spinner label="Restoring session" />;
  if (!user) return null;

  return (
    <div className="flex min-h-screen">
      <aside className="flex w-60 shrink-0 flex-col border-r border-ink-800 bg-ink-900">
        <div className="border-b border-ink-800 px-5 py-4">
          <p className="font-mono text-lg font-bold tracking-tight">
            Decrypt<span className="text-accent">0rX</span>
          </p>
          <p className="mt-0.5 text-[11px] uppercase tracking-widest text-ink-400">
            HTTPS interception
          </p>
        </div>

        <nav className="flex-1 space-y-1 p-3">
          {NAV.filter((item) => can(item.minimum)).map((item) => {
            const active =
              item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition ${
                  active
                    ? "bg-accent/10 text-accent"
                    : "text-ink-300 hover:bg-ink-800 hover:text-white"
                }`}
              >
                <span className="w-4 text-center text-xs">{item.icon}</span>
                {item.label}
              </Link>
            );
          })}
        </nav>

        <div className="border-t border-ink-800 p-3">
          <p className="truncate px-2 text-xs text-ink-200">{user.email}</p>
          <p className="px-2 text-[11px] uppercase tracking-wide text-ink-400">
            {user.role}
          </p>
          <button
            onClick={signOut}
            className="mt-2 w-full rounded-lg px-2 py-1.5 text-left text-xs text-ink-400 transition hover:bg-ink-800 hover:text-bad"
          >
            Sign out
          </button>
        </div>
      </aside>

      <main className="flex-1 overflow-x-hidden">{children}</main>
    </div>
  );
}

export function PageHeader({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children?: React.ReactNode;
}) {
  return (
    <header className="flex flex-wrap items-start justify-between gap-4 border-b border-ink-800 bg-ink-900/40 px-8 py-5">
      <div>
        <h1 className="text-xl font-semibold text-white">{title}</h1>
        {description && <p className="mt-1 text-sm text-ink-400">{description}</p>}
      </div>
      <div className="flex items-center gap-2">{children}</div>
    </header>
  );
}
