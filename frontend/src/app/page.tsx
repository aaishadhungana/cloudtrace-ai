import { BackendStatus } from "@/components/BackendStatus";

export default function OverviewPage() {
  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight text-white">Overview</h1>
        <p className="mt-1 text-sm text-slate-400">
          Cloud identity security and attack-path analysis.
        </p>
      </header>
      <BackendStatus />
      <section className="rounded-lg border border-dashed border-line p-8 text-center">
        <p className="text-sm text-slate-400">
          No environments yet. Environment management is added in the next milestone.
        </p>
      </section>
    </div>
  );
}