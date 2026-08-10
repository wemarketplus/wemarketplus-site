import { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { Download, Image as ImageIcon, Loader2 } from 'lucide-react';
import { useAppSelector } from '@/app/hooks';
import { Modal } from '@/shared/ui/feedback';
import type { ExpenseReceiptRecord } from '../types/fieldTypes';
import {
  fetchReceiptFile,
  isPreviewableImage,
  saveBlob,
} from '../utils/receiptFiles';

interface ReceiptFileButtonProps {
  receipt: ExpenseReceiptRecord;
  /** Compact rendering for the trip table, where space is tight. */
  compact?: boolean;
}

/**
 * View (or save) the file attached to a receipt.
 *
 * WHY A BUTTON AND NOT AN `<a href>`/`<img src>`: the file is served only from
 * an authenticated, tenant-scoped route, so a bare href or img would fire a
 * request without the bearer token and 401. We fetch the bytes with the token
 * and render them from an object URL.
 *
 * Images preview in a modal; a PDF downloads instead of rendering inline. That
 * split is deliberate — an inline PDF runs in a viewer we do not control, and a
 * receipt is a file the worker wants to keep anyway.
 */
export function ReceiptFileButton({ receipt, compact }: ReceiptFileButtonProps) {
  const token = useAppSelector((s) => s.auth?.token ?? null);
  const [isFetching, setFetching] = useState(false);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);

  // An object URL pins its Blob in memory until revoked. Revoke on unmount and
  // whenever it is replaced, or paging through a month of receipts leaks every
  // photo the user opened.
  useEffect(
    () => () => {
      if (previewUrl) URL.revokeObjectURL(previewUrl);
    },
    [previewUrl],
  );

  if (!receipt.hasFile) return null;

  const open = async () => {
    setFetching(true);
    const result = await fetchReceiptFile(receipt.id, token);
    setFetching(false);

    if (!result.blob) {
      // 404 here means the row is not this tenant's (or does not exist) — the
      // server answers both identically on purpose, so we do too.
      const message =
        result.status === 0
          ? 'Could not reach the server.'
          : result.status === 404
            ? 'That receipt is no longer available.'
            : 'Could not open that receipt.';
      toast.error(message);
      return;
    }

    if (isPreviewableImage(receipt.storageMimeType)) {
      setPreviewUrl(URL.createObjectURL(result.blob));
      return;
    }
    saveBlob(result.blob, result.filename ?? receipt.originalFilename ?? undefined);
  };

  const isImage = isPreviewableImage(receipt.storageMimeType);
  const Icon = isFetching ? Loader2 : isImage ? ImageIcon : Download;

  return (
    <>
      <button
        type="button"
        onClick={() => void open()}
        disabled={isFetching}
        title={receipt.originalFilename ?? 'Receipt file'}
        className="inline-flex items-center gap-1 text-[11px] font-semibold text-primary hover:underline disabled:opacity-60"
      >
        <Icon className={`h-3 w-3 ${isFetching ? 'animate-spin' : ''}`} />
        {compact ? 'Photo' : isImage ? 'View photo' : 'Download'}
      </button>

      <Modal
        open={previewUrl !== null}
        onClose={() => setPreviewUrl(null)}
        title={receipt.originalFilename ?? 'Receipt'}
        size="lg"
      >
        {previewUrl && (
          <img
            src={previewUrl}
            alt={`Receipt ${receipt.originalFilename ?? ''}`}
            className="mx-auto max-h-[60vh] w-auto rounded-lg"
          />
        )}
      </Modal>
    </>
  );
}
