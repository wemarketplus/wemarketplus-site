// The PDF export streams a binary body, which RTK Query's JSON base query
// doesn't handle well. Trigger it as a direct authenticated download instead.
export function reportPdfUrl(): string {
  const base = import.meta.env.VITE_API_BASE_URL || '/api';
  return `${base}/reports/export/pdf`;
}
