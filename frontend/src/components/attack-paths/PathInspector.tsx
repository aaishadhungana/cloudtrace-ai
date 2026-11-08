import Link from "next/link";
import { DecisionBadge } from "@/components/analysis/DecisionBadge";
import { EvidenceList } from "@/components/analysis/EvidenceList";
import type { Selection } from "@/components/attack-paths/PathGraph";
import type { AttackPathDetail } from "@/lib/attack-path-types";
import { RELATIONSHIP_LABELS, humanize } from "@/lib/labels";

interface PathInspectorProps {
  path: AttackPathDetail;
  selection: Selection;
  basePath: string;
}

function recordList(value: unknown): Record<string, unknown>[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter(
    (item): item is Record<string, unknown> =>
      typeof item === "object" && item !== null && !Array.isArray(item),
  );
}

export function PathInspector({ path, selection, basePath }: PathInspectorProps) {
  if (selection === null) {
    return (
      <p className="text-sm text-slate-500">
        Select a node or an edge in the graph, or a step below, to see its supporting details.
      </p>
    );
  }

  if (selection.kind === "node") {
    const node = path.nodes[selection.index];
    return (
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="text-base font-semibold text-white">{node.name}</h3>
          <span className="text-xs text-slate-400">{humanize(node.type)}</span>
          {node.is_sensitive && (
            <span className="rounded-full bg-red-500/15 px-2 py-0.5 text-xs text-red-300">
              Sensitive
            </span>
          )}
          {node.is_external && (
            <span className="rounded-full bg-sky-500/15 px-2 py-0.5 text-xs text-sky-300">
              External
            </span>
          )}
        </div>
        <dl className="grid grid-cols-[8rem_1fr] gap-y-1 text-xs">
          <dt className="text-slate-500">Position in path</dt>
          <dd className="text-slate-300">{humanize(node.position)}</dd>
          <dt className="text-slate-500">ARN</dt>
          <dd className="break-all font-mono text-slate-300">{node.arn}</dd>
        </dl>
        {node.kind === "identity" && node.id && (
          <Link
            href={`${basePath}/identities/${node.id}`}
            className="inline-block text-sm text-accent hover:underline"
          >
            Open identity
          </Link>
        )}
      </div>
    );
  }

  const edge = path.edges[selection.index];
  const source = path.nodes[selection.index];
  const target = path.nodes[selection.index + 1];
  const step = path.evidence[selection.index];

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <p className="text-sm text-slate-400">
          Step {selection.index + 1}: {source.name} to {target.name}
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="text-base font-semibold text-white">
            {edge.relationships.map((item) => RELATIONSHIP_LABELS[item]).join(" + ")}
          </h3>
          <DecisionBadge decision={edge.decision} />
        </div>
        <p className="font-mono text-xs text-slate-500">{edge.actions.join(", ")}</p>
      </div>
      {edge.assumption && (
        <p className="rounded-md border border-sky-500/30 bg-sky-500/10 p-3 text-sm text-sky-200">
          Unverified: {edge.assumption}
        </p>
      )}
      {edge.notes
        .filter((note) => note !== edge.assumption)
        .map((note) => (
          <p key={note} className="text-xs text-slate-400">
            {note}
          </p>
        ))}
      <div className="space-y-2">
        <h4 className="text-xs font-medium uppercase tracking-wide text-slate-500">
          Effective access
        </h4>
        <EvidenceList items={recordList(step?.relationships)} />
      </div>
      <div className="space-y-2">
        <h4 className="text-xs font-medium uppercase tracking-wide text-slate-500">
          Supporting statements
        </h4>
        <EvidenceList items={recordList(step?.statements)} />
      </div>
    </div>
  );
}