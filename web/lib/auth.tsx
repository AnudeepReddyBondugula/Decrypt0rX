"use client";

import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api, setToken } from "./api";
import type { Role, User } from "./types";

interface AuthState {
  user: User | null;
  loading: boolean;
  signIn: (email: string, password: string) => Promise<void>;
  signOut: () => void;
  can: (minimum: Role) => boolean;
}

const RANK: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 };

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    // Restore the session on first paint; an expired token resolves to null.
    api
      .me()
      .then(setUser)
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  const signIn = useCallback(async (email: string, password: string) => {
    const result = await api.login(email, password);
    setToken(result.access_token);
    setUser(result.user);
  }, []);

  const signOut = useCallback(() => {
    setToken(null);
    setUser(null);
    router.push("/login");
  }, [router]);

  const can = useCallback(
    (minimum: Role) => (user ? RANK[user.role] >= RANK[minimum] : false),
    [user],
  );

  return (
    <AuthContext.Provider value={{ user, loading, signIn, signOut, can }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside <AuthProvider>");
  return context;
}
