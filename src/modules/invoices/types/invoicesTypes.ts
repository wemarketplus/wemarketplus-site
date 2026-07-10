import type { ID, ISODateString, PaginationParams } from '@/shared/types';
import type { InvoiceStatus } from '../constants/invoicesConstants';

// Mirrors wemarketplus-backend/src/invoices/dto/invoice-response.dto.ts.
// Invoices are tenant-scoped billing records. `invoiceNumber` is auto-generated
// server-side when omitted on create.
export interface InvoiceRecord {
  id: ID;
  tenantId: ID;
  invoiceNumber: string;
  companyName: string;
  applicationId: ID | null;
  amount: number;
  feeModel: string | null;
  status: InvoiceStatus;
  dueDate: string | null;
  notes: string | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

// Mirrors CreateInvoiceDto — companyName + amount required, rest optional.
export interface CreateInvoiceRequest {
  companyName: string;
  amount: number;
  invoiceNumber?: string;
  applicationId?: string;
  feeModel?: string;
  status?: InvoiceStatus;
  dueDate?: string;
  notes?: string;
}

// Mirrors UpdateInvoiceDto — any subset of the create fields.
export type UpdateInvoiceRequest = Partial<CreateInvoiceRequest>;

// GET /invoices supports pagination + an optional status filter.
export interface ListInvoicesQuery extends PaginationParams {
  status?: InvoiceStatus;
}
