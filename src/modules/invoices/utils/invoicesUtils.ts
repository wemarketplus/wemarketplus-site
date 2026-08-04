import { opt, optOrNull } from '@/shared/ui/entity';
import type { CreateInvoiceRequest, UpdateInvoiceRequest } from '../types/invoicesTypes';
import type { InvoiceFormValues } from '../schema/invoiceSchema';
import type { InvoiceRecord } from '../types/invoicesTypes';
import type { InvoiceStatus } from '../constants/invoicesConstants';

// Form values -> POST /invoices body. Nullable optionals go as explicit nulls so
// clearing one in the edit form actually clears the column — an omitted key in a
// PATCH means "leave unchanged".
//
// invoiceNumber is the exception and MUST stay `opt`: its column is NOT NULL and
// the service fills it with `dto.invoiceNumber ?? generateInvoiceNumber()`. An
// absent key generates one; an explicit null slips past `??` on create but
// violates NOT NULL on update. status is likewise NOT NULL with a DB default.
export function toCreateInvoice(values: InvoiceFormValues): CreateInvoiceRequest {
  return {
    companyName: values.companyName.trim(),
    amount: values.amount,
    ...opt('invoiceNumber', values.invoiceNumber),
    ...optOrNull('feeModel', values.feeModel),
    ...optOrNull('dueDate', values.dueDate),
    ...optOrNull('applicationId', values.applicationId),
    ...optOrNull('notes', values.notes),
    ...(values.status ? { status: values.status as InvoiceStatus } : {}),
  };
}

// PATCH body is the same shape (partial); the backend accepts any subset.
export function toUpdateInvoice(values: InvoiceFormValues): UpdateInvoiceRequest {
  return toCreateInvoice(values);
}

// Seeds the edit form from an existing record (nulls -> '').
export function toInvoiceFormValues(invoice: InvoiceRecord): InvoiceFormValues {
  return {
    companyName: invoice.companyName,
    amount: invoice.amount,
    status: invoice.status,
    invoiceNumber: invoice.invoiceNumber ?? '',
    feeModel: invoice.feeModel ?? '',
    dueDate: invoice.dueDate ?? '',
    applicationId: invoice.applicationId ?? '',
    notes: invoice.notes ?? '',
  };
}

// USD money formatter shared across the invoices table + form.
const MONEY = new Intl.NumberFormat('en-US', {
  style: 'currency',
  currency: 'USD',
});
export const formatMoney = (value: number | null): string =>
  value === null ? '—' : MONEY.format(value);
