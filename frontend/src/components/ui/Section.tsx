import type { ReactNode } from "react";
import { cardClass } from "@/components/ui/styles";

export function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className={`${cardClass} space-y-3`}>
      <h2 className="text-sm font-medium uppercase tracking-wide text-slate-400">{title}</h2>
      {children}
    </section>
  );
}