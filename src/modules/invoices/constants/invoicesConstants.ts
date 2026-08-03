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
  { name: 'dueDate', label: 'Due date', type: 'text', placeholder: 'YYYY-MM-DD' },
  { name: 'applicationId', label: 'Application', type: 'lookup', placeholder: 'No application' },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true },
];
