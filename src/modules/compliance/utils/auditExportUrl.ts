// /audit/export is a CSV download, not a JSON call — build the authenticated
// download URL for the browser to open directly.
export function auditExportUrl(params?: { action?: string; resource?: string }): string {
  const base = import.meta.env.VITE_API_BASE_URL || '/api';
  const qs = params ? '?' + new URLSearchParams(params as Record<string, string>).toString() : '';
  return `${base}/audit/export${qs}`;
}
