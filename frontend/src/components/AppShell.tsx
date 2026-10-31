"use client";

import { useEffect } from "react";
import type { ReactNode } from "react";
import { usePathname, useRouter } from "next/navigation";
import { Sidebar } from "@/components/layout/Sidebar";
import { FullPageSpinner } from "@/components/ui/Spinner";
import { useAuth } from "@/lib/auth-context";

const PUBLIC_PATHS = new Set(["/login", "/register"]);

export function AppShell({ children }: { children: ReactNode }) {
  const { state } = useAuth();
  const pathname = usePathname();
  const router = useRouter();
  const isPublicPath = PUBLIC_PATHS.has(pathname);

  useEffect(() => {
    if (state.status === "anonymous" && !isPublicPath) {
      router.replace("/login");
    }
    if (state.status === "authenticated" && isPublicPath) {
      router.replace("/");
    }
  }, [state.status, isPublicPath, router]);

  if (state.status === "loading") {
    return <FullPageSpinner />;
  }

  if (state.status === "anonymous") {
    if (!isPublicPath) {
      return <FullPageSpinner />;
    }
    return (
      <main className="flex min-h-screen items-center justify-center px-4 py-10">{children}</main>
    );
  }

  if (isPublicPath) {
    return <FullPageSpinner />;
  }

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="min-w-0 flex-1 px-10 py-8">{children}</main>
    </div>
  );
}