import { z } from 'zod';

// Create/edit invoice form — mirrors CreateInvoiceDto
// (wemarketplus-backend/src/invoices/dto/create-invoice.dto.ts). companyName and
// amount are required; the rest are optional and stripped when blank before
// sending. dueDate is an ISO date string.
// amount inputs register with valueAsNumber, so a blank field yields NaN. z4's
// z.number() rejects NaN before any .refine runs, so guard NaN explicitly: allow
// it through the union, then reject it with a "required" message. A real value
// below zero fails min(0).
export const invoiceSchema = z.object({
  companyName: z.string().min(1, 'Company is required').max(200),
  amount: z
    .number()
    .min(0, 'Amount cannot be negative')
    .or(z.nan())
    .refine((v) => !Number.isNaN(v), 'Amount is required'),
  status: z
    .enum(['draft', 'sent', 'paid', 'overdue', 'cancelled'])
    .optional()
    .or(z.literal('')),
  invoiceNumber: z.string().max(60).optional(),
  feeModel: z.string().max(200).optional(),
  dueDate: z.string().optional(),
  applicationId: z
    .string()
    .uuid('Application id must be a valid UUID')
    .optional()
    .or(z.literal('')),
  notes: z.string().optional(),
});

export type InvoiceFormValues = z.infer<typeof invoiceSchema>;
