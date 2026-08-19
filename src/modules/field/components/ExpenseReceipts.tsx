import { useState } from 'react';
import { toast } from 'sonner';
import { ExternalLink, Paperclip, Plus } from 'lucide-react';
import { Button, Card, CardContent, DatePicker, Input, Label, Select } from '@/shared/ui/core';
import { Pill } from '@/shared/ui/data-display';
import { Modal } from '@/shared/ui/feedback';
import {
  useCreateExpenseReceiptMutation,
  useListExpenseReceiptsQuery,
} from '../api/mileageApi';
import { ExpenseType } from '../types/fieldTypes';
import type { ApprovalStatus } from '../types/fieldTypes';
import { AttachReceiptDialog, EXPENSE_TYPE_LABELS } from './AttachReceiptDialog';
import { ReceiptFileButton } from './ReceiptFileButton';

const APPROVAL_PILL: Record<ApprovalStatus, 'y' | 'g' | 'r'> = {
  pending: 'y',
  approved: 'g',
  rejected: 'r',
};

const money = (value: number) =>
  Number(value).toLocaleString('en-US', {
    style: 'currency',
    currency: 'USD',
  });

function todayLocal(): string {
  const now = new Date();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  return `${now.getFullYear()}-${month}-${day}`;
}

/**
 * Expense receipts attached to field work.
 *
 * PROOF NOW COMES IN TWO FORMS and this panel handles both:
 *
 *  - "Attach photo" uploads the file to the server, which validates it by its
 *    leading bytes and serves it back only through an authenticated,
 *    tenant-scoped route. This is the primary path.
 *  - "Add link" is the original flow, kept because every receipt filed before
 *    uploads existed is a `receiptUrl` and those claims are still open. It is
 *    also the escape hatch for proof that genuinely lives elsewhere (a vendor
 *    portal invoice that is a login away, not a file).
 *
 * The trip-level attach on the Mileage table is where a receipt tied to a
 * specific drive should be filed; this panel is for receipts with no trip (a
 * conference meal, supplies) and for reviewing everything together.
 *
 * Approval stays read-only here. Reviewing is Admin/Owner/Manager on the
 * backend (`PATCH /expense-receipts/:id/review`), so showing a field worker an
 * approve button would only produce a 403.
 */
export function ExpenseReceipts() {
  const { data, isLoading } = useListExpenseReceiptsQuery({ limit: 50 });
  const [create, { isLoading: isSaving }] = useCreateExpenseReceiptMutation();

  const [open, setOpen] = useState(false);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [form, setForm] = useState({
    expenseDate: todayLocal(),
    expenseType: ExpenseType.Parking as ExpenseType,
    amount: '',
    receiptUrl: '',
    notes: '',
  });

  const receipts = data?.data ?? [];

  const submit = async () => {
    const amount = Number(form.amount);
    if (!Number.isFinite(amount) || amount <= 0) {
      toast.error('Enter the amount.');
      return;
    }
    try {
      await create({
        expenseDate: form.expenseDate,
        expenseType: form.expenseType,
        amount,
        receiptUrl: form.receiptUrl.trim() || undefined,
        notes: form.notes.trim() || undefined,
      }).unwrap();
      setOpen(false);
      setForm((f) => ({ ...f, amount: '', receiptUrl: '', notes: '' }));
      toast.success('Receipt added');
    } catch {
      toast.error('Could not add that receipt.');
    }
  };

  return (
    <Card>
      <CardContent className="px-0 pb-0 pt-0">
        <header className="flex flex-wrap items-center gap-3 px-6 py-4">
          <div className="min-w-0 flex-1">
            <h2 className="text-sm font-semibold text-foreground">
              Expense receipts
            </h2>
            <p className="text-[11px] text-muted-soft">
              Parking, tolls and meals claimed alongside your mileage
            </p>
          </div>
          {/* Upload is the primary action; the link form is secondary now that
              real proof can be stored, so it gets the ghost treatment. */}
          <Button variant="ghost" size="sm" onClick={() => setOpen(true)}>
            <Plus className="h-4 w-4" /> Add link
          </Button>
          <Button size="sm" onClick={() => setUploadOpen(true)}>
            <Paperclip className="h-4 w-4" /> Attach photo
          </Button>
        </header>

        {isLoading ? (
          <p className="px-6 pb-5 text-xs text-muted-soft">Loading receipts…</p>
        ) : receipts.length === 0 ? (
          <p className="px-6 pb-5 text-xs text-muted-soft">
            No receipts submitted yet.
          </p>
        ) : (
          <ul className="divide-y divide-border border-t border-border">
            {receipts.map((receipt) => (
              <li
                key={receipt.id}
                className="flex flex-wrap items-center gap-3 px-6 py-3"
              >
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-foreground">
                    {EXPENSE_TYPE_LABELS[receipt.expenseType]} ·{' '}
                    {money(receipt.amount)}
                  </p>
                  <p className="text-[11px] text-muted-soft">
                    {receipt.expenseDate}
                    {receipt.mileageLogId ? ' · on a trip' : ''}
                    {receipt.notes ? ` · ${receipt.notes}` : ''}
                  </p>
                </div>
                {/* Renders nothing for link-only rows, so the two proof forms
                    coexist on the same list without either being special-cased
                    into hiding the other. */}
                <ReceiptFileButton receipt={receipt} />
                {receipt.receiptUrl && (
                  <a
                    href={receipt.receiptUrl}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="inline-flex items-center gap-1 text-[11px] text-primary hover:underline"
                  >
                    <ExternalLink className="h-3 w-3" /> Link
                  </a>
                )}
                <Pill tone={APPROVAL_PILL[receipt.approvalStatus]}>
                  {receipt.approvalStatus}
                </Pill>
              </li>
            ))}
          </ul>
        )}
      </CardContent>

      {/* Standalone upload: no trip, so the dialog defaults the date to today. */}
      <AttachReceiptDialog
        open={uploadOpen}
        onClose={() => setUploadOpen(false)}
        trip={null}
      />

      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title="Add receipt link"
        footer={
          <>
            <Button variant="ghost" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button onClick={submit} disabled={isSaving}>
              {isSaving ? 'Saving…' : 'Add receipt'}
            </Button>
          </>
        }
      >
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div>
            <Label htmlFor="er-date">Date</Label>
            <DatePicker
              id="er-date"
              value={form.expenseDate}
              onChange={(e) =>
                setForm((f) => ({ ...f, expenseDate: e.target.value }))
              }
            />
          </div>
          <div>
            <Label htmlFor="er-type">Type</Label>
            <Select
              id="er-type"
              value={form.expenseType}
              onChange={(e) =>
                setForm((f) => ({
                  ...f,
                  expenseType: e.target.value as ExpenseType,
                }))
              }
            >
              {Object.values(ExpenseType).map((t) => (
                <option key={t} value={t}>
                  {EXPENSE_TYPE_LABELS[t]}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <Label htmlFor="er-amount">Amount</Label>
            <Input
              id="er-amount"
              type="number"
              step="0.01"
              min="0"
              value={form.amount}
              onChange={(e) =>
                setForm((f) => ({ ...f, amount: e.target.value }))
              }
            />
          </div>
          <div>
            <Label htmlFor="er-url">Receipt image link</Label>
            <Input
              id="er-url"
              type="url"
              value={form.receiptUrl}
              onChange={(e) =>
                setForm((f) => ({ ...f, receiptUrl: e.target.value }))
              }
              placeholder="https://…"
            />
            {/* Kept honest: this form stores a REFERENCE, and the file stays
                wherever the worker put it — under their permissions, editable
                after approval. "Attach photo" is the one that stores proof. */}
            <p className="mt-1 text-[11px] text-muted-soft">
              Stores a link only. To keep the receipt itself with the claim, use
              Attach photo instead.
            </p>
          </div>
          <div className="sm:col-span-2">
            <Label htmlFor="er-notes">Notes</Label>
            <Input
              id="er-notes"
              value={form.notes}
              onChange={(e) => setForm((f) => ({ ...f, notes: e.target.value }))}
            />
          </div>
        </div>
      </Modal>
    </Card>
  );
}
