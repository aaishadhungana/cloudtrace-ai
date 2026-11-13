import type {
  AttackPathAnalysisContent,
  FindingAnalysisContent,
  RemediationStep,
  SecuritySummaryContent,
} from "@/lib/ai-types";

function TextBlock({ title, text }: { title: string; text: string }) {
  return (
    <div className="space-y-1">
      <h3 className="text-xs font-medium uppercase tracking-wide text-slate-500">{title}</h3>
      <p className="text-sm leading-relaxed text-slate-200">{text}</p>
    </div>
  );
}

function BulletBlock({ title, items }: { title: string; items: string[] }) {
  if (items.length === 0) {
    return null;
  }
  return (
    <div className="space-y-1">
      <h3 className="text-xs font-medium uppercase tracking-wide text-slate-500">{title}</h3>
      <ul className="list-disc space-y-1 pl-5 text-sm text-slate-200">
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </div>
  );
}

function RemediationBlock({ steps }: { steps: RemediationStep[] }) {
  if (steps.length === 0) {
    return null;
  }
  return (
    <div className="space-y-2">
      <h3 className="text-xs font-medium uppercase tracking-wide text-slate-500">
        Suggested remediation
      </h3>
      <ol className="space-y-3">
        {steps.map((step) => (
          <li key={step.action} className="rounded-md border border-line bg-ink p-3 text-sm">
            <p className="font-medium text-slate-100">{step.action}</p>
            <p className="mt-1 text-slate-300">{step.rationale}</p>
            <p className="mt-1 text-xs text-amber-300">Verify first: {step.verify_before_applying}</p>
          </li>
        ))}
      </ol>
    </div>
  );
}

export function FindingAiContent({ content }: { content: FindingAnalysisContent }) {
  return (
    <div className="space-y-4">
      <TextBlock title="What was detected" text={content.what_was_detected} />
      <TextBlock title="Why it is risky" text={content.why_it_is_risky} />
      <TextBlock title="Potential impact" text={content.potential_impact} />
      <BulletBlock title="What the evidence establishes" items={content.evidence_established} />
      <BulletBlock title="What remains uncertain" items={content.remaining_uncertainty} />
      <RemediationBlock steps={content.remediation} />
    </div>
  );
}

export function PathAiContent({ content }: { content: AttackPathAnalysisContent }) {
  const steps = [...content.steps].sort((left, right) => left.step - right.step);
  return (
    <div className="space-y-4">
      <TextBlock title="Overview" text={content.overview} />
      <div className="space-y-1">
        <h3 className="text-xs font-medium uppercase tracking-wide text-slate-500">Step by step</h3>
        <ol className="space-y-1 text-sm text-slate-200">
          {steps.map((item) => (
            <li key={item.step}>
              <span className="mr-2 font-mono text-xs text-slate-500">{item.step}</span>
              {item.explanation}
            </li>
          ))}
        </ol>
      </div>
      <TextBlock title="Potential impact" text={content.potential_impact} />
      <TextBlock title="Why it deserves attention" text={content.why_it_deserves_attention} />
      <BulletBlock
        title="Verify before claiming exploitability"
        items={content.verify_before_claiming_exploitability}
      />
      <RemediationBlock steps={content.remediation} />
    </div>
  );
}

export function SummaryAiContent({ content }: { content: SecuritySummaryContent }) {
  return (
    <div className="space-y-4">
      <TextBlock title="Overview" text={content.overview} />
      {content.priorities.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-medium uppercase tracking-wide text-slate-500">
            Priorities
          </h3>
          <ol className="space-y-3">
            {content.priorities.map((item) => (
              <li key={item.title} className="rounded-md border border-line bg-ink p-3 text-sm">
                <p className="font-medium text-slate-100">{item.title}</p>
                <p className="mt-1 text-slate-300">{item.why}</p>
                <p className="mt-1 text-xs text-sky-300">Recommended: {item.recommended_action}</p>
              </li>
            ))}
          </ol>
        </div>
      )}
      <BulletBlock title="Caveats" items={content.caveats} />
    </div>
  );
}