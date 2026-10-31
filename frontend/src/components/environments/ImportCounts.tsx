import type { ImportMetadata } from "@/lib/types";

export function ImportCounts({ metadata }: { metadata: ImportMetadata }) {
  const items = [
    { label: "Identities", value: metadata.identity_count },
    { label: "Resources", value: metadata.resource_count },
    { label: "Policies", value: metadata.policy_count },
    { label: "Statements", value: metadata.statement_count },
    { label: "Sensitive", value: metadata.sensitive_resource_count },
  ];
  return (
    <dl className="grid grid-cols-5 gap-3">
      {items.map((item) => (
        <div key={item.label}>
          <dt className="text-xs text-slate-500">{item.label}</dt>
          <dd className="text-lg font-semibold text-white">{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}