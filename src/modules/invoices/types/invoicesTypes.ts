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
  /**
   * Revenue attribution — see the same pair on the backend Invoice entity. Null
   * means "not hospice-attributed" (a Grants-side invoice), not missing data.
   */
  prospectId: ID | null;
  referralSourceId: ID | null;
  amount: number;
  feeModel: string | null;
  status: InvoiceStatus;
  dueDate: string | null;
  notes: string | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

// Mirrors CreateInvoiceDto — companyName + amount required, rest optional.
// `null` on a nullable optional means "clear this column"; an omitted key means
// "leave unchanged" — see optOrNull in shared/ui/entity/formValues. invoiceNumber
// is NOT nullable (auto-generated when absent), so it is never sent as null.
export interface CreateInvoiceRequest {
  companyName: string;
  amount: number;
  invoiceNumber?: string;
  applicationId?: string | null;
  prospectId?: string | null;
  referralSourceId?: string | null;
  feeModel?: string | null;
  status?: InvoiceStatus;
  dueDate?: string | null;
  notes?: string | null;
}

// Mirrors UpdateInvoiceDto — any subset of the create fields.
export type UpdateInvoiceRequest = Partial<CreateInvoiceRequest>;

// GET /invoices supports pagination + an optional status filter.
export interface ListInvoicesQuery extends PaginationParams {
  status?: InvoiceStatus;
}
