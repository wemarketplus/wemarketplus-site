// Uploaded receipts are NOT reachable by URL. The bytes live outside any static
// serving root and come back only from GET /expense-receipts/:id/file, which is
// Bearer-authenticated and checks that the row belongs to the caller's tenant —
// deliberately, because a receipt photo can carry a patient name or address and
// must not be fetchable by guessing an id.
//
// That rules out `<img src>` and `window.open`: neither carries the
// Authorization header (see app/baseQuery prepareHeaders), so both would 401.
// We fetch with the token and hand the caller a Blob to render or save. Same
// shape as modules/admin/utils/authenticatedDownload.ts, which solved this for
// CSV/XLSX exports.

const apiBase = (): string => import.meta.env.VITE_API_BASE_URL || '/api';

/**
 * Mirrors RECEIPT_MAX_BYTES in
 * wemarketplus-backend/src/mileage/receipt-file-type.util.ts.
 *
 * ADVISORY ONLY. It exists so a worker on a phone signal is told "too big"
 * instantly instead of after a 30-second upload that 413s. The cap that
 * actually holds is the server's — this constant drifting out of sync makes the
 * UX worse, never the system less safe.
 */
export const RECEIPT_MAX_BYTES = 10 * 1024 * 1024;

/**
 * What the file picker offers. Also advisory: the server decides what a file
 * really is from its leading bytes, so this list steers the picker rather than
 * enforcing anything. Matches the server's allow-list so the two agree.
 */
export const RECEIPT_ACCEPT = 'image/jpeg,image/png,image/webp,application/pdf';

export const receiptFileUrl = (receiptId: string): string =>
  `${apiBase()}/expense-receipts/${receiptId}/file`;

export interface ReceiptFileResult {
  /** HTTP status, or 0 on a network error, so callers can show 401/403/404. */
  status: number;
  blob?: Blob;
  /** Filename from Content-Disposition, used when saving to disk. */
  filename?: string;
}

/** Fetch a receipt's file with the caller's bearer token. */
export async function fetchReceiptFile(
  receiptId: string,
  token: string | null,
): Promise<ReceiptFileResult> {
  let response: Response;
  try {
    response = await fetch(receiptFileUrl(receiptId), {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
  } catch {
    return { status: 0 };
  }
  if (!response.ok) return { status: response.status };

  return {
    status: response.status,
    blob: await response.blob(),
    filename: filenameFromDisposition(
      response.headers.get('Content-Disposition'),
    ),
  };
}

/** Save a fetched blob to disk under `filename`. */
export function saveBlob(blob: Blob, filename?: string): void {
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = objectUrl;
  if (filename) anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectUrl);
}

/** True when the server's SNIFFED type is something we can show inline. */
export const isPreviewableImage = (mimeType: string | null): boolean =>
  mimeType === 'image/jpeg' ||
  mimeType === 'image/png' ||
  mimeType === 'image/webp';

function filenameFromDisposition(header: string | null): string | undefined {
  if (!header) return undefined;
  const match = /filename\*?=(?:UTF-8'')?"?([^"';]+)"?/i.exec(header);
  return match ? decodeURIComponent(match[1]) : undefined;
}
