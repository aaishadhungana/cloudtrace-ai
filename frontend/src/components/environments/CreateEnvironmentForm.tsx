"use client";

import { Plus } from "lucide-react";
import { useState } from "react";
import type { FormEvent } from "react";
import { Button } from "@/components/ui/Button";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { Field } from "@/components/ui/Field";
import { cardClass, inputClass } from "@/components/ui/styles";
import { createEnvironment } from "@/lib/api";

export function CreateEnvironmentForm({ onCreated }: { onCreated: () => void }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await createEnvironment({
        name: name.trim(),
        description: description.trim() || null,
      });
      setName("");
      setDescription("");
      onCreated();
    } catch (caught) {
      setError(caught);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className={`${cardClass} space-y-4`}>
      <h2 className="text-sm font-medium uppercase tracking-wide text-slate-400">
        New environment
      </h2>
      <Field
        label="Name"
        name="name"
        required
        maxLength={120}
        placeholder="acme-production"
        value={name}
        onChange={(event) => setName(event.target.value)}
      />
      <div className="space-y-1.5">
        <label htmlFor="environment-description" className="block text-sm font-medium text-slate-300">
          Description
        </label>
        <textarea
          id="environment-description"
          rows={2}
          maxLength={2000}
          className={inputClass}
          value={description}
          onChange={(event) => setDescription(event.target.value)}
        />
      </div>
      {error !== null && <ErrorBanner error={error} />}
      <Button type="submit" loading={submitting}>
        <Plus className="h-4 w-4" aria-hidden />
        Create environment
      </Button>
    </form>
  );
}