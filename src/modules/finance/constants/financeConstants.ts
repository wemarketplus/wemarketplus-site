// Finance status enums — mirror backend InvoiceRecordStatus, ExpenseType, ApprovalStatus.
export const INVOICE_STATUS = {
  Draft: 'draft',
  Sent: 'sent',
  Paid: 'paid',
  Overdue: 'overdue',
  Cancelled: 'cancelled',
} as const;
export type InvoiceStatus = (typeof INVOICE_STATUS)[keyof typeof INVOICE_STATUS];

export const EXPENSE_TYPE = {
  Parking: 'parking',
  Tolls: 'tolls',
  Meals: 'meals',
  Supplies: 'supplies',
  Event: 'event',
  Other: 'other',
} as const;
export type ExpenseType = (typeof EXPENSE_TYPE)[keyof typeof EXPENSE_TYPE];

export const APPROVAL_STATUS = {
  Pending: 'pending',
  Approved: 'approved',
  Rejected: 'rejected',
} as const;
export type ApprovalStatus = (typeof APPROVAL_STATUS)[keyof typeof APPROVAL_STATUS];
