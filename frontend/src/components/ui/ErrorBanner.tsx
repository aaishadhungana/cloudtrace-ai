import { CircleAlert } from "lucide-react";
import { describeError } from "@/lib/errors";

export function ErrorBanner({ error }: { error: unknown }) {
  const { message, issues } = describeError(error);
  return (
    <div
      role="alert"
      className="rounded-md border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300"
    >
      <p className="flex items-center gap-2 font-medium">
        <CircleAlert className="h-4 w-4 shrink-0" aria-hidden />
        {message}
      </p>
      {issues.length > 0 && (
        <ul className="mt-2 max-h-56 space-y-1 overflow-auto pl-6 text-xs">
          {issues.map((issue, index) => (
            <li key={`${issue.path}-${index}`}>
              <code className="mr-1 text-red-200">{issue.path || "$"}</code>
              {issue.message}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}