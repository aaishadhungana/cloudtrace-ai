const dateTimeFormatter = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "short",
});

export function formatDateTime(isoString: string): string {
  return dateTimeFormatter.format(new Date(isoString));
}