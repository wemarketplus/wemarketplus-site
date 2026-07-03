// CSV/XLSX exports are binary downloads, not RTK Query JSON calls. The API is
// Bearer-authenticated (app/baseQuery prepareHeaders), so a plain <a href> or
// window.open would omit the Authorization header and 401 — we fetch the file
// with the token, then trigger a blob download from the response.
const apiBase = (): string => import.meta.env.VITE_API_BASE_URL || '/api';

export const trainingProvidersCsvUrl = (): string => `${apiBase()}/training-providers/export/csv`;
export const trainingProvidersXlsxUrl = (): string => `${apiBase()}/training-providers/export/xlsx`;
export const rosterExportUrl = (applicationId: string): string =>
  `${apiBase()}/training-rosters/export/${applicationId}`;

/** Fetch an authenticated file URL and save it to disk. Returns the HTTP status
 *  (or 0 on a network error) so callers can surface 401/403 to the user. */
export async function downloadTrainingExport(
  url: string,
  token: string | null,
): Promise<number> {
  let response: Response;
  try {
    response = await fetch(url, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
  } catch {
    return 0;
  }
  if (!response.ok) return response.status;

  const blob = await response.blob();
  const filename = filenameFromDisposition(response.headers.get('Content-Disposition'));
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = objectUrl;
  if (filename) anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectUrl);
  return response.status;
}

/** Parse a filename out of a Content-Disposition header, if present. */
function filenameFromDisposition(header: string | null): string | undefined {
  if (!header) return undefined;
  const match = /filename\*?=(?:UTF-8'')?"?([^"';]+)"?/i.exec(header);
  return match ? decodeURIComponent(match[1]) : undefined;
}
