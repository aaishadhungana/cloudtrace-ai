"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { Download } from "lucide-react";
import { useCallback, useState } from "react";
import { SummaryAiContent } from "@/components/ai/AiContent";
import { SeverityBadge } from "@/components/analysis/SeverityBadge";
import { ClassificationBadge } from "@/components/attack-paths/ClassificationBadge";
import { Button } from "@/components/ui/Button";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { Section } from "@/components/ui/Section";
import { Spinner } from "@/components/ui/Spinner";
import { downloadReportMarkdown, getReport } from "@/lib/insight-api";
import { formatDateTime } from "@/lib/format";
import { SEVERITY_ORDER } from "@/lib/labels";
import { useApiResource } from "@/lib/use-api-resource";

export default function ReportPage() {
  const { id, runId } = useParams<{ id: string; runId: string }>();
  const base = `/environments/${id}/runs/${runId}`;
  const loadReport = useCallback((signal: AbortSignal) => getReport(id, runId, signal), [id, runId]);
  const { state } = useApiResource(loadReport);
  const [downloading, setDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState<unknown>(null);

  async function handleDownload() {
    setDownloading(true);
    setDownloadError(null);
    try {
      const blob = await downloadReportMarkdown(id, runId);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `cloudtrace-report-${runId}.md`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (caught) {
      setDownloadError(caught);
    } finally {
      setDownloading(false);
    }
  }

  if (state.kind === "loading") {
    return <Spinner label="Building report" />;
  }
  if (state.kind === "error") {
    return <ErrorBanner error={state.error} />;
  }
  const report = state.data;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-white">Security report</h2>
          <p className="text-xs text-slate-500">
            {report.environment.name} · generated {formatDateTime(report.generated_at)}
          </p>
        </div>
        <Button variant="secondary" loading={downloading} onClick={handleDownload}>
          <Download className="h-4 w-4" aria-hidden />
          Download Markdown
        </Button>
      </div>
      {downloadError !== null && <ErrorBanner error={downloadError} />}

      <Section title="Analysis scope">
        <dl className="grid grid-cols-[11rem_1fr] gap-y-2 text-sm">
          <dt className="text-slate-500">Environment</dt>
          <dd className="text-slate-200">
            {report.environment.name} ({report.environment.cloud_provider.toUpperCase()})
          </dd>
          <dt className="text-slate-500">Import</dt>
          <dd className="text-slate-200">
            {report.scope.import_source} ({formatDateTime(report.scope.import_created_at)})
          </dd>
          <dt className="text-slate-500">Engine version</dt>
          <dd className="text-slate-200">{report.scope.analysis_version}</dd>
          <dt className="text-slate-500">Modeled</dt>
          <dd className="text-slate-200">
            {report.scope.identity_count} identities, {report.scope.resource_count} resources (
            {report.scope.sensitive_resource_count} sensitive), {report.scope.policy_count}{" "}
            policies, {report.scope.statement_count} statements
          </dd>
        </dl>
      </Section>

      <Section title="Finding counts">
        <div className="flex flex-wrap gap-2 text-sm text-slate-300">
          <span>{report.finding_total} findings:</span>
          {SEVERITY_ORDER.map((severity) => (
            <span key={severity} className="capitalize">
              {report.severity_counts[severity]} {severity}
            </span>
          ))}
        </div>
      </Section>

      <Section title="Highest-priority findings">
        {report.findings.length === 0 && (
          <p className="text-sm text-slate-500">No findings were reported.</p>
        )}
        <ul className="space-y-4">
          {report.findings.map((finding) => (
            <li key={finding.id} className="space-y-2 rounded-md border border-line bg-ink p-4">
              <div className="flex flex-wrap items-center gap-3">
                <SeverityBadge severity={finding.severity} />
                <span className="font-mono text-xs text-slate-400">
                  {finding.rule_id} · score {finding.risk_score}
                </span>
              </div>
              <Link
                href={`${base}/findings/${finding.id}`}
                className="block text-sm font-medium text-slate-100 hover:text-accent"
              >
                {finding.title}
              </Link>
              <p className="text-sm text-slate-300">{finding.explanation}</p>
              <p className="text-sm text-slate-400">Remediation: {finding.remediation}</p>
            </li>
          ))}
        </ul>
        {report.findings_not_shown > 0 && (
          <p className="text-xs text-slate-500">
            {report.findings_not_shown} more findings are not listed here.
          </p>
        )}
      </Section>

      <Section title="Attack paths">
        {report.attack_paths.length === 0 && (
          <p className="text-sm text-slate-500">
            No attack paths were found. This does not prove that sensitive resources are safe.
          </p>
        )}
        <ul className="space-y-2">
          {report.attack_paths.map((path) => (
            <li key={path.id} className="flex flex-wrap items-center gap-3 text-sm">
              <SeverityBadge severity={path.severity} />
              <ClassificationBadge classification={path.classification} />
              <Link href={`${base}/attack-paths/${path.id}`} className="text-slate-200 hover:text-accent">
                {path.summary}
              </Link>
            </li>
          ))}
        </ul>
        {report.attack_paths_not_shown > 0 && (
          <p className="text-xs text-slate-500">
            {report.attack_paths_not_shown} more attack paths are not listed here.
          </p>
        )}
        {report.paths_incomplete && (
          <p className="text-xs text-amber-300">
            Attack-path discovery reached a limit, so this list may be incomplete.
          </p>
        )}
      </Section>

      {report.ai_summary !== null && (
        <section
          aria-label="AI-generated summary"
          className="space-y-3 rounded-lg border border-violet-500/30 bg-violet-500/5 p-5"
        >
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-sm font-medium uppercase tracking-wide text-violet-300">
              AI summary
            </h2>
            <span className="rounded-full bg-violet-500/20 px-2.5 py-0.5 text-xs font-medium text-violet-200">
              AI-generated
            </span>
          </div>
          <p className="text-xs text-slate-400">{report.ai_summary.notice}</p>
          <SummaryAiContent content={report.ai_summary.content} />
        </section>
      )}

      <Section title="Limitations">
        <ul className="list-disc space-y-2 pl-5 text-sm text-slate-300">
          {report.limitations.map((limitation) => (
            <li key={limitation}>{limitation}</li>
          ))}
        </ul>
      </Section>
    </div>
  );
}