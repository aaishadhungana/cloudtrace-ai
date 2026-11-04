import { formatValue, humanize } from "@/lib/labels";

export function EvidenceList({ items }: { items: Record<string, unknown>[] }) {
  if (items.length === 0) {
    return <p className="text-sm text-slate-500">No evidence recorded.</p>;
  }
  return (
    <ul className="space-y-3">
      {items.map((item, index) => (
        <li key={index} className="rounded-md border border-line bg-ink p-3">
          <p className="mb-2 text-xs font-medium uppercase tracking-wide text-accent">
            {humanize(String(item.kind ?? "evidence"))}
          </p>
          <dl className="grid grid-cols-[9rem_1fr] gap-x-3 gap-y-1 text-xs">
            {Object.entries(item)
              .filter(([key]) => key !== "kind")
              .map(([key, value]) => (
                <div key={key} className="contents">
                  <dt className="text-slate-500">{humanize(key)}</dt>
                  <dd className="break-all font-mono text-slate-300">{formatValue(value)}</dd>
                </div>
              ))}
          </dl>
        </li>
      ))}
    </ul>
  );
}