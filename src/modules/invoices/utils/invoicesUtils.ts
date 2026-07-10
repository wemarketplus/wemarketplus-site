import { opt } from '@/shared/ui/entity';
import type { CreateInvoiceRequest, UpdateInvoiceRequest } from '../types/invoicesTypes';
import type { InvoiceFormValues } from '../schema/invoiceSchema';
import type { InvoiceRecord } from '../types/invoicesTypes';
import type { InvoiceStatus } from '../constants/invoicesConstants';

// Form values -> POST /invoices body. Drops blank optionals so we never send
// empty strings the DTO would reject (applicationId is IsUUID gated; status is
// an enum). companyName + amount are always sent.
export function toCreateInvoice(values: InvoiceFormValues): CreateInvoiceRequest {
  return {
    companyName: values.companyName.trim(),
    amount: values.amount,
    ...opt('invoiceNumber', values.invoiceNumber),
    ...opt('feeModel', values.feeModel),
    ...opt('dueDate', values.dueDate),
    ...opt('applicationId', values.applicationId),
    ...opt('notes', values.notes),
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
