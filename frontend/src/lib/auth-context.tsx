"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import type { ReactNode } from "react";
import {
  getMe,
  login as loginRequest,
  register as registerRequest,
  setUnauthorizedHandler,
} from "@/lib/api";
import { clearToken, readToken, writeToken } from "@/lib/token-store";
import type { User } from "@/lib/types";

type AuthState =
  | { status: "loading" }
  | { status: "anonymous" }
  | { status: "authenticated"; user: User };

interface AuthContextValue {
  state: AuthState;
  signIn: (email: string, password: string) => Promise<void>;
  signUp: (email: string, password: string) => Promise<void>;
  signOut: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ status: "loading" });

  const signOut = useCallback(() => {
    clearToken();
    setState({ status: "anonymous" });
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(signOut);
    return () => setUnauthorizedHandler(null);
  }, [signOut]);

  useEffect(() => {
    let cancelled = false;
    const request = readToken() ? getMe() : Promise.resolve(null);
    request
      .then((user) => {
        if (!cancelled) {
          setState(user ? { status: "authenticated", user } : { status: "anonymous" });
        }
      })
      .catch(() => {
        if (!cancelled) {
          setState({ status: "anonymous" });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const signIn = useCallback(async (email: string, password: string) => {
    const token = await loginRequest(email, password);
    writeToken(token.access_token);
    try {
      const user = await getMe();
      setState({ status: "authenticated", user });
    } catch (error) {
      clearToken();
      throw error;
    }
  }, []);

  const signUp = useCallback(
    async (email: string, password: string) => {
      await registerRequest(email, password);
      await signIn(email, password);
    },
    [signIn],
  );

  const value = useMemo(
    () => ({ state, signIn, signUp, signOut }),
    [state, signIn, signUp, signOut],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (context === null) {
    throw new Error("useAuth must be used inside AuthProvider");
  }
  return context;
}