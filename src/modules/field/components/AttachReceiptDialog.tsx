import { useEffect, useRef, useState } from 'react';
import { toast } from 'sonner';
import { Paperclip } from 'lucide-react';
import { Button, DatePicker, Input, Label, Select } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import { useUploadExpenseReceiptMutation } from '../api/mileageApi';
import { ExpenseType } from '../types/fieldTypes';
import type { MileageLogRecord } from '../types/fieldTypes';
import { RECEIPT_ACCEPT, RECEIPT_MAX_BYTES } from '../utils/receiptFiles';
import { routeLabel } from '../utils/tripLocations';

export const EXPENSE_TYPE_LABELS: Record<ExpenseType, string> = {
  parking: 'Parking',
  tolls: 'Tolls',
  meals: 'Meals',
  supplies: 'Supplies',
  event: 'Event',
  other: 'Other',
};

/** Today as YYYY-MM-DD in LOCAL time — an expense date is a calendar day, not
 *  an instant, so `toISOString()` would file an evening receipt as tomorrow. */
function todayLocal(): string {
  const now = new Date();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  return `${now.getFullYear()}-${month}-${day}`;
}

const megabytes = (bytes: number) => `${(bytes / (1024 * 1024)).toFixed(1)} MB`;

interface AttachReceiptDialogProps {
  open: boolean;
  onClose: () => void;
  /**
   * The trip this receipt belongs to, or null for a standalone receipt. When
   * set, the receipt is filed against that mileage log and the expense date
   * defaults to the trip's date — the whole point of "right there on the same
   * entry" is that the worker never re-keys what the trip already knows.
   */
  trip: MileageLogRecord | null;
}

/**
 * Photograph a gas/toll/parking receipt and attach it to a trip.
 *
 * This is a REAL upload: the bytes go to the server, which validates them by
 * their leading bytes (not the extension or the declared type), generates the
 * stored filename itself, and files it under the tenant. The old flow — "upload
 * it to your Drive and paste the link" — left the proof for a reimbursement
 * claim outside the system that adjudicates it.
 *
 * Deliberately NO `capture` attribute on the input: `capture="environment"`
 * forces the camera on mobile and hides the photo library, which breaks the
 * common case of a receipt photographed at the pump and filed that evening.
 * Without it the OS offers camera AND library.
 */
export function AttachReceiptDialog({
  open,
  onClose,
  trip,
}: AttachReceiptDialogProps) {
  const [upload, { isLoading: isUploading }] = useUploadExpenseReceiptMutation();
  const fileInput = useRef<HTMLInputElement>(null);

  const [file, setFile] = useState<File | null>(null);
  /**
   * Why the oversize message is STATE and not just a toast: a toast is gone in
   * four seconds, and the thing it was explaining — the file picker — still
   * reads "no file selected" afterwards, which is indistinguishable from never
   * having picked one. The reason the file was refused has to stay next to the
   * field that refused it.
   */
  const [rejected, setRejected] = useState<string | null>(null);
  const [expenseType, setExpenseType] = useState<ExpenseType>(
    ExpenseType.Parking,
  );
  const [amount, setAmount] = useState('');
  const [notes, setNotes] = useState('');
  const [expenseDate, setExpenseDate] = useState(trip?.date ?? todayLocal());

  // Reopening for a different trip must not inherit the previous trip's date or
  // a half-filled amount — a receipt filed against the wrong day is a rejected
  // expense claim.
  useEffect(() => {
    if (!open) return;
    setFile(null);
    setRejected(null);
    setAmount('');
    setNotes('');
    setExpenseType(ExpenseType.Parking);
    setExpenseDate(trip?.date ?? todayLocal());
    if (fileInput.current) fileInput.current.value = '';
  }, [open, trip?.date, trip?.id]);

  /**
   * Size is checked HERE, when the file is chosen — not only in submit().
   *
   * The submit-time guard alone meant a worker could pick a 40 MB photo, fill in
   * the date, type, amount and notes, press Attach receipt, and only then be
   * told the file was never viable: every keystroke after the pick was wasted,
   * and on a phone the picker is several taps back. It also let the field sit
   * there displaying an accepted-looking "receipt.jpg · 41.8 MB" in the
   * meantime, which is what "no file-size validation" describes even though a
   * cap did exist further down the flow.
   *
   * The rejected file is dropped from state AND the input is cleared, so there
   * is no way to submit it: `value = ''` matters because re-picking the SAME
   * file would otherwise fire no change event at all, leaving the worker
   * tapping a picker that appears to do nothing.
   *
   * The server's cap (multer `limits.fileSize` plus a byte-length check in
   * ExpenseReceiptsService) is still the one that holds — this is the fast,
   * local half of the same rule, and the 413 branch below covers the case where
   * the two ever disagree.
   */
  const pick = (chosen: File | null) => {
    if (chosen && chosen.size > RECEIPT_MAX_BYTES) {
      const message =
        `${chosen.name} is ${megabytes(chosen.size)}. ` +
        `Receipts must be ${megabytes(RECEIPT_MAX_BYTES)} or smaller — ` +
        `photograph it again at a lower resolution, or attach a PDF.`;
      setRejected(message);
      setFile(null);
      toast.error(`That file is too large (${megabytes(chosen.size)}).`);
      if (fileInput.current) fileInput.current.value = '';
      return;
    }
    setRejected(null);
    setFile(chosen);
  };

  const submit = async () => {
    if (!file) {
      toast.error('Choose a photo or PDF of the receipt.');
      return;
    }
    // Advisory only — the server enforces the real cap. This just saves a
    // doomed upload over a phone connection.
    if (file.size > RECEIPT_MAX_BYTES) {
      toast.error(
        `That file is ${megabytes(file.size)}. The limit is ${megabytes(RECEIPT_MAX_BYTES)}.`,
      );
      return;
    }
    const parsed = Number(amount);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      toast.error('Enter the amount on the receipt.');
      return;
    }

    try {
      await upload({
        mileageLogId: trip?.id,
        expenseDate,
        expenseType,
        amount: parsed,
        notes: notes.trim() || undefined,
        file,
      }).unwrap();
      toast.success(trip ? 'Receipt attached to this trip.' : 'Receipt added.');
      onClose();
    } catch (error) {
      // 415 is the server refusing the file's actual content, which is a
      // different problem for the user than a network failure — a phone that
      // shot HEIC, say. Say which so they know whether retrying helps.
      const status = (error as { status?: number } | undefined)?.status;
      if (status === 415) {
        toast.error('That file is not a JPEG, PNG, WebP or PDF.');
      } else if (status === 413) {
        toast.error(`Receipts must be under ${megabytes(RECEIPT_MAX_BYTES)}.`);
      } else {
        toast.error('Could not attach that receipt.');
      }
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      /*
        A trip with no endpoints recorded titled this dialog
        "Attach receipt · — → —". See routeLabel: the arrow is drawn only when
        there are two places to join, and a routeless trip is identified by the
        day it was logged instead — which is what the worker recognises it by
        anyway, and is never blank.
      */
      title={
        trip
          ? `Attach receipt · ${routeLabel(trip) ?? `trip on ${trip.date}`}`
          : 'Attach receipt'
      }
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={isUploading}>
            {isUploading ? 'Uploading…' : 'Attach receipt'}
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <Label htmlFor="ar-file">Receipt photo or PDF</Label>
          <input
            ref={fileInput}
            id="ar-file"
            type="file"
            accept={RECEIPT_ACCEPT}
            onChange={(e) => pick(e.target.files?.[0] ?? null)}
            className="mt-1 block w-full text-xs text-muted file:mr-3 file:rounded-md file:border-0 file:bg-primary/15 file:px-3 file:py-1.5 file:text-xs file:font-semibold file:text-primary"
          />
          <p
            className={
              rejected
                ? 'mt-1 text-[11px] text-destructive'
                : 'mt-1 text-[11px] text-muted-soft'
            }
            role={rejected ? 'alert' : undefined}
          >
            {rejected ??
              (file
                ? `${file.name} · ${megabytes(file.size)}`
                : `JPEG, PNG, WebP or PDF, up to ${megabytes(RECEIPT_MAX_BYTES)}.`)}
          </p>
        </div>

        <div>
          <Label htmlFor="ar-date">Date</Label>
          <DatePicker
            id="ar-date"
            value={expenseDate}
            onChange={(e) => setExpenseDate(e.target.value)}
          />
        </div>
        <div>
          <Label htmlFor="ar-type">Type</Label>
          <Select
            id="ar-type"
            value={expenseType}
            onChange={(e) => setExpenseType(e.target.value as ExpenseType)}
          >
            {Object.values(ExpenseType).map((type) => (
              <option key={type} value={type}>
                {EXPENSE_TYPE_LABELS[type]}
              </option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="ar-amount">Amount</Label>
          <Input
            id="ar-amount"
            type="number"
            step="0.01"
            min="0"
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
            placeholder="8.40"
          />
        </div>
        <div>
          <Label htmlFor="ar-notes">Notes</Label>
          <Input
            id="ar-notes"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Toll — I-95 northbound"
          />
        </div>
      </div>

      {trip && (
        <p className="mt-4 flex items-center gap-1.5 text-[11px] text-muted-soft">
          <Paperclip className="h-3 w-3" />
          Filed against this trip, so it travels with it on the expense report.
        </p>
      )}
    </Modal>
  );
}
