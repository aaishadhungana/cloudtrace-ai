"use client";

import "@xyflow/react/dist/style.css";
import { Background, Controls, Handle, MarkerType, Position, ReactFlow } from "@xyflow/react";
import type { Edge, Node, NodeProps } from "@xyflow/react";
import { useMemo } from "react";
import type { AttackPathDetail } from "@/lib/attack-path-types";
import { RELATIONSHIP_LABELS, humanize } from "@/lib/labels";

export type Selection =
  | { kind: "node"; index: number }
  | { kind: "edge"; index: number }
  | null;

type PathNodeData = {
  name: string;
  typeLabel: string;
  position: string;
  isSensitive: boolean;
  isExternal: boolean;
};

type PathFlowNode = Node<PathNodeData, "path">;

const NODE_SPACING = 300;
const POSITION_LABELS: Record<string, string> = {
  start: "Start",
  pivot: "Pivot",
  target: "Target",
};

function PathNode({ data, selected }: NodeProps<PathFlowNode>) {
  const border = data.isSensitive ? "border-red-500/70" : selected ? "border-accent" : "border-line";
  return (
    <div
      className={`w-56 rounded-lg border-2 bg-panel px-3 py-2 ${border} ${
        selected ? "ring-2 ring-accent/40" : ""
      }`}
    >
      <Handle type="target" position={Position.Left} isConnectable={false} />
      <p className="text-[10px] font-medium uppercase tracking-wide text-slate-500">
        {POSITION_LABELS[data.position] ?? data.position} · {data.typeLabel}
      </p>
      <p className="truncate text-sm font-medium text-white" title={data.name}>
        {data.name}
      </p>
      {(data.isSensitive || data.isExternal) && (
        <div className="mt-1 flex gap-1.5">
          {data.isSensitive && (
            <span className="rounded-full bg-red-500/15 px-2 py-0.5 text-[10px] text-red-300">
              Sensitive
            </span>
          )}
          {data.isExternal && (
            <span className="rounded-full bg-sky-500/15 px-2 py-0.5 text-[10px] text-sky-300">
              External
            </span>
          )}
        </div>
      )}
      <Handle type="source" position={Position.Right} isConnectable={false} />
    </div>
  );
}

const nodeTypes = { path: PathNode };

const DECISION_COLORS: Record<string, string> = {
  allowed: "#fbbf24",
  conditional: "#38bdf8",
};

function edgeIndex(edgeId: string): number {
  return Number(edgeId.replace("edge-", ""));
}

interface PathGraphProps {
  path: AttackPathDetail;
  selection: Selection;
  onSelect: (selection: Selection) => void;
}

export function PathGraph({ path, selection, onSelect }: PathGraphProps) {
  const nodes = useMemo<PathFlowNode[]>(
    () =>
      path.nodes.map((node, index) => ({
        id: node.arn,
        type: "path",
        position: { x: index * NODE_SPACING, y: 0 },
        draggable: false,
        selected: selection?.kind === "node" && selection.index === index,
        data: {
          name: node.name,
          typeLabel: humanize(node.type),
          position: node.position,
          isSensitive: node.is_sensitive,
          isExternal: node.is_external,
        },
      })),
    [path, selection],
  );

  const edges = useMemo<Edge[]>(
    () =>
      path.edges.map((edge, index) => {
        const color = DECISION_COLORS[edge.decision] ?? "#94a3b8";
        const selected = selection?.kind === "edge" && selection.index === index;
        return {
          id: `edge-${index}`,
          source: edge.source,
          target: edge.target,
          type: "smoothstep",
          label: edge.relationships.map((item) => RELATIONSHIP_LABELS[item]).join(" + "),
          selected,
          markerEnd: { type: MarkerType.ArrowClosed, color },
          style: {
            stroke: color,
            strokeWidth: selected ? 3.5 : 2,
            strokeDasharray: edge.assumption !== null ? "6 4" : undefined,
          },
          labelStyle: { fill: "#e2e8f0", fontSize: 11 },
          labelBgStyle: { fill: "#111a2b" },
          labelBgPadding: [6, 3],
          labelBgBorderRadius: 4,
        };
      }),
    [path, selection],
  );

  return (
    <div
      role="group"
      aria-label="Attack path graph"
      className="h-[340px] overflow-hidden rounded-lg border border-line"
    >
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        colorMode="dark"
        nodesDraggable={false}
        nodesConnectable={false}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        onNodeClick={(_, node) => {
          const index = path.nodes.findIndex((item) => item.arn === node.id);
          if (index >= 0) {
            onSelect({ kind: "node", index });
          }
        }}
        onEdgeClick={(_, edge) => onSelect({ kind: "edge", index: edgeIndex(edge.id) })}
        onPaneClick={() => onSelect(null)}
      >
        <Background />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}