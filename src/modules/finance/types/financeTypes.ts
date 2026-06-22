import type { ID, ISODateString } from '@/shared/types';
import type { ExpenseType, InvoiceStatus, ApprovalStatus } from '../constants/financeConstants';

// Mirrors wemarketplus-backend invoices, mileage-logs, expense-receipts, revenue,
// and financial-settings DTOs.

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

export interface MileageLogRecord {
  id: ID;
  tenantId: ID;
  userId: ID;
  date: string;
  fromLocation: string | null;
  toLocation: string | null;
  purpose: string | null;
  miles: number;
  reimbursementRate: number;
  reimbursementAmount: number | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}
export interface CreateMileageLogRequest {
  miles: number;
  date?: string;
  fromLocation?: string;
  toLocation?: string;
  purpose?: string;
  reimbursementRate?: number;
}

export interface ExpenseReceiptRecord {
  id: ID;
  tenantId: ID;
  userId: ID;
  mileageLogId: ID | null;
  expenseDate: string;
  expenseType: ExpenseType;
  amount: number;
  receiptUrl: string | null;
  receiptFilename: string | null;
  notes: string | null;
  approvalStatus: ApprovalStatus;
  approvedBy: ID | null;
  approvedAt: ISODateString | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}
export interface CreateExpenseReceiptRequest {
  expenseDate: string;
  expenseType: ExpenseType;
  amount: number;
  mileageLogId?: string;
  receiptUrl?: string;
  receiptFilename?: string;
  notes?: string;
}

export interface RevenueRecord {
  id: ID;
  tenantId: ID;
  applicationId: ID | null;
  companyId: ID | null;
  wibId: ID | null;
  feeModel: string | null;
  calculatedSuccessFee: number | null;
  grantAwardAmount: number | null;
  invoiceStatus: string;
  invoiceSentDate: string | null;
  paymentReceivedDate: string | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}
export interface UpdateRevenueRequest {
  invoiceStatus?: string;
  paymentReceivedDate?: string;
  invoiceSentDate?: string;
}

export interface FinancialSetting {
  settingKey: string;
  settingValue: string;
}
