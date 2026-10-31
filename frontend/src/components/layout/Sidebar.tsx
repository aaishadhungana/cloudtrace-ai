"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Cloud, LayoutDashboard, LogOut, ShieldCheck } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useAuth } from "@/lib/auth-context";

interface NavItem {
  label: string;
  href: string;
  icon: LucideIcon;
}

const NAV_ITEMS: NavItem[] = [
  { label: "Overview", href: "/", icon: LayoutDashboard },
  { label: "Environments", href: "/environments", icon: Cloud },
];

function isActive(pathname: string, href: string): boolean {
  return href === "/" ? pathname === "/" : pathname.startsWith(href);
}

export function Sidebar() {
  const pathname = usePathname();
  const { state, signOut } = useAuth();

  return (
    <aside className="flex w-60 shrink-0 flex-col border-r border-line bg-panel px-4 py-6">
      <div className="mb-8 flex items-center gap-2 px-2">
        <ShieldCheck className="h-6 w-6 text-accent" aria-hidden />
        <span className="text-lg font-semibold tracking-tight text-white">CloudTrace AI</span>
      </div>
      <nav className="flex flex-1 flex-col gap-1" aria-label="Primary">
        {NAV_ITEMS.map((item) => {
          const active = isActive(pathname, item.href);
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              aria-current={active ? "page" : undefined}
              className={`flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors ${
                active
                  ? "bg-accent/10 text-accent"
                  : "text-slate-400 hover:bg-white/5 hover:text-slate-200"
              }`}
            >
              <Icon className="h-4 w-4" aria-hidden />
              {item.label}
            </Link>
          );
        })}
      </nav>
      {state.status === "authenticated" && (
        <div className="border-t border-line pt-4">
          <p className="truncate px-2 text-xs text-slate-500" title={state.user.email}>
            {state.user.email}
          </p>
          <button
            type="button"
            onClick={signOut}
            className="mt-2 flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm text-slate-400 transition-colors hover:bg-white/5 hover:text-slate-200"
          >
            <LogOut className="h-4 w-4" aria-hidden />
            Sign out
          </button>
        </div>
      )}
    </aside>
  );
}