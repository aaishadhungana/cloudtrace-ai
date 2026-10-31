import { useId } from "react";
import type { InputHTMLAttributes } from "react";
import { inputClass } from "@/components/ui/styles";

interface FieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  hint?: string;
}

export function Field({ label, hint, id, ...rest }: FieldProps) {
  const generatedId = useId();
  const inputId = id ?? generatedId;
  return (
    <div className="space-y-1.5">
      <label htmlFor={inputId} className="block text-sm font-medium text-slate-300">
        {label}
      </label>
      <input id={inputId} className={inputClass} {...rest} />
      {hint && <p className="text-xs text-slate-500">{hint}</p>}
    </div>
  );
}