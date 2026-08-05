import type { EntityField } from '@/shared/ui/entity';
import type { InvoiceFormValues } from '../schema/invoiceSchema';

export const INVOICES_PAGE_SIZE = 20;

// Mirrors backend InvoiceRecordStatus (invoices/invoices.constants.ts).
export const INVOICE_STATUS = {
  Draft: 'draft',
  Sent: 'sent',
  Paid: 'paid',
  Overdue: 'overdue',
  Cancelled: 'cancelled',
} as const;
export type InvoiceStatus = (typeof INVOICE_STATUS)[keyof typeof INVOICE_STATUS];

export const INVOICE_STATUS_OPTIONS: ReadonlyArray<{ value: InvoiceStatus; label: string }> = [
  { value: 'draft', label: 'Draft' },
  { value: 'sent', label: 'Sent' },
  { value: 'paid', label: 'Paid' },
  { value: 'overdue', label: 'Overdue' },
  { value: 'cancelled', label: 'Cancelled' },
];

// Field descriptors driving the create/edit modal (EntityFormModal). Order here
// is render order; `full` spans both grid columns. invoiceNumber is optional
// (auto-generated when blank).
export const INVOICE_FIELDS: ReadonlyArray<EntityField<InvoiceFormValues>> = [
  { name: 'companyName', label: 'Company', full: true, placeholder: 'Acme Corp' },
  { name: 'amount', label: 'Amount', type: 'number', placeholder: '0.00' },
  {
    name: 'status',
    label: 'Status',
    type: 'select',
    options: INVOICE_STATUS_OPTIONS.map((o) => ({ value: o.value, label: o.label })),
  },
  { name: 'invoiceNumber', label: 'Invoice number', placeholder: 'auto-generated' },
  { name: 'feeModel', label: 'Fee model', placeholder: 'success fee, flat…' },
  { name: 'dueDate', label: 'Due date', type: 'date' },
  // DEPRECATED — NOT NEEDED, PENDING REMOVAL. The Application picker links an
  // invoice to a grant application; the Grants domain was hidden from the UI on
  // 2026-08-06 per the product owner, so the field is removed from the form. The
  // column (invoices.applicationId) and its DTO/schema handling stay — existing
  // links are preserved and simply left untouched by the form. Re-add this field
  // (and the `lookups` prop in InvoiceFormModal) to restore.
  // { name: 'applicationId', label: 'Application', type: 'lookup', placeholder: 'No application' },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true },
];
