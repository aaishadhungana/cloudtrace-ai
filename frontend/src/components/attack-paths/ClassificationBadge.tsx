import type { PathClassification } from "@/lib/attack-path-types";

const STYLES: Record<PathClassification, string> = {
  supported: "bg-amber-500/15 text-amber-300",
  potential: "bg-sky-500/15 text-sky-300",
};

const TITLES: Record<PathClassification, string> = {
  supported: "Every step is allowed by the modeled permissions",
  potential: "At least one step depends on a condition or an unverified assumption",
};

export function ClassificationBadge({ classification }: { classification: PathClassification }) {
  return (
    <span
      title={TITLES[classification]}
      className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-medium capitalize ${STYLES[classification]}`}
    >
      {classification}
    </span>
  );
}