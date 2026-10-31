"use client";

import Link from "next/link";
import { ShieldCheck } from "lucide-react";
import { useState } from "react";
import type { FormEvent } from "react";
import { Button } from "@/components/ui/Button";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { Field } from "@/components/ui/Field";
import { useAuth } from "@/lib/auth-context";

interface AuthFormProps {
  mode: "login" | "register";
}

const COPY = {
  login: {
    title: "Sign in",
    subtitle: "Access your cloud environments.",
    submit: "Sign in",
    alternatePrompt: "No account yet?",
    alternateLabel: "Create one",
    alternateHref: "/register",
  },
  register: {
    title: "Create account",
    subtitle: "Start analyzing cloud identity risk.",
    submit: "Create account",
    alternatePrompt: "Already registered?",
    alternateLabel: "Sign in",
    alternateHref: "/login",
  },
} as const;

export function AuthForm({ mode }: AuthFormProps) {
  const { signIn, signUp } = useAuth();
  const copy = COPY[mode];
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      if (mode === "login") {
        await signIn(email.trim(), password);
      } else {
        await signUp(email.trim(), password);
      }
    } catch (caught) {
      setError(caught);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="w-full max-w-sm">
      <div className="mb-6 flex items-center gap-2">
        <ShieldCheck className="h-7 w-7 text-accent" aria-hidden />
        <span className="text-xl font-semibold tracking-tight text-white">CloudTrace AI</span>
      </div>
      <div className="rounded-lg border border-line bg-panel p-6">
        <h1 className="text-lg font-semibold text-white">{copy.title}</h1>
        <p className="mt-1 text-sm text-slate-400">{copy.subtitle}</p>
        <form onSubmit={handleSubmit} className="mt-5 space-y-4">
          <Field
            label="Email"
            name="email"
            type="email"
            autoComplete="email"
            required
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
          <Field
            label="Password"
            name="password"
            type="password"
            autoComplete={mode === "login" ? "current-password" : "new-password"}
            required
            minLength={mode === "register" ? 12 : undefined}
            maxLength={128}
            hint={mode === "register" ? "At least 12 characters." : undefined}
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
          {error !== null && <ErrorBanner error={error} />}
          <Button type="submit" loading={submitting} className="w-full">
            {copy.submit}
          </Button>
        </form>
      </div>
      <p className="mt-4 text-center text-sm text-slate-400">
        {copy.alternatePrompt}{" "}
        <Link href={copy.alternateHref} className="text-accent hover:underline">
          {copy.alternateLabel}
        </Link>
      </p>
    </div>
  );
}