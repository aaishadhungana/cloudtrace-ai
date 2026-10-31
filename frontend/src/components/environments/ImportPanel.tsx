"use client";

import { CheckCircle2, FileJson, Upload } from "lucide-react";
import { useRef, useState } from "react";
import type { ChangeEvent } from "react";
import { ImportCounts } from "@/components/environments/ImportCounts";
import { Button } from "@/components/ui/Button";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { cardClass, inputClass } from "@/components/ui/styles";
import { createImport, getSampleDocument, listSamples } from "@/lib/api";
import { useApiResource } from "@/lib/use-api-resource";
import type { ImportRecord } from "@/lib/types";

const MAX_IMPORT_BYTES = 1_048_576;

interface PreparedImport {
  body: string;
  source: string;
}

interface ImportPanelProps {
  environmentId: string;
  onImported: () => void;
}

function toSourceLabel(filename: string): string {
  const cleaned = filename.replace(/[^A-Za-z0-9._() -]/g, "_").slice(0, 255);
  return cleaned || "upload.json";
}

export function ImportPanel({ environmentId, onImported }: ImportPanelProps) {
  const { state: samples } = useApiResource(listSamples);
  const fileInput = useRef<HTMLInputElement>(null);
  const [selectedSample, setSelectedSample] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ImportRecord | null>(null);
  const [error, setError] = useState<unknown>(null);

  const sampleList = samples.kind === "ready" ? samples.data : [];
  const sampleName = selectedSample ?? sampleList[0]?.name ?? "";
  const sampleDescription = sampleList.find((item) => item.name === sampleName)?.description;

  async function runImport(prepare: () => Promise<PreparedImport>) {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const { body, source } = await prepare();
      const record = await createImport(environmentId, body, source);
      setResult(record);
      onImported();
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }

  async function handleFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) {
      return;
    }
    await runImport(async () => {
      if (file.size > MAX_IMPORT_BYTES) {
        throw new Error("File is larger than the 1 MiB import limit");
      }
      return { body: await file.text(), source: toSourceLabel(file.name) };
    });
  }

  async function handleSample() {
    if (!sampleName) {
      return;
    }
    await runImport(async () => ({
      body: await getSampleDocument(sampleName),
      source: `${sampleName}.json`,
    }));
  }

  return (
    <section className={`${cardClass} space-y-5`}>
      <div>
        <h2 className="text-sm font-medium uppercase tracking-wide text-slate-400">
          Import configuration
        </h2>
        <p className="mt-1 text-sm text-slate-400">
          Upload a JSON file using schema version 1.0, or load a bundled sample.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <input
          ref={fileInput}
          type="file"
          accept="application/json,.json"
          className="hidden"
          onChange={handleFile}
        />
        <Button variant="secondary" loading={busy} onClick={() => fileInput.current?.click()}>
          <Upload className="h-4 w-4" aria-hidden />
          Upload JSON file
        </Button>
      </div>

      <div className="space-y-2 border-t border-line pt-4">
        <label htmlFor="sample-select" className="block text-sm font-medium text-slate-300">
          Bundled sample
        </label>
        <div className="flex flex-wrap items-center gap-3">
          <select
            id="sample-select"
            className={`${inputClass} max-w-xs`}
            value={sampleName}
            disabled={sampleList.length === 0 || busy}
            onChange={(event) => setSelectedSample(event.target.value)}
          >
            {sampleList.map((item) => (
              <option key={item.name} value={item.name}>
                {item.title}
              </option>
            ))}
          </select>
          <Button variant="secondary" loading={busy} disabled={!sampleName} onClick={handleSample}>
            <FileJson className="h-4 w-4" aria-hidden />
            Import sample
          </Button>
        </div>
        {sampleDescription && <p className="text-xs text-slate-500">{sampleDescription}</p>}
        {samples.kind === "error" && <ErrorBanner error={samples.error} />}
      </div>

      {error !== null && <ErrorBanner error={error} />}
      {result !== null && (
        <div className="space-y-3 rounded-md border border-emerald-500/30 bg-emerald-500/10 p-4">
          <p className="flex items-center gap-2 text-sm font-medium text-emerald-300">
            <CheckCircle2 className="h-4 w-4" aria-hidden />
            Imported {result.import_source}
          </p>
          <ImportCounts metadata={result.sanitized_metadata} />
        </div>
      )}
    </section>
  );
}