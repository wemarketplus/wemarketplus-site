// Grant-CRM invoices — tenant-scoped billing records. Create + edit UI (no
// delete; the backend exposes none) built on the shared entity kit
// (@/shared/ui/entity). Mutations require the `manage_invoices` permission.
export { InvoicesPage } from './pages/InvoicesPage';
export {
  invoicesApi,
  useListInvoicesQuery,
  useGetInvoiceQuery,
  useCreateInvoiceMutation,
  useUpdateInvoiceMutation,
} from './api/invoicesApi';
export type {
  InvoiceRecord,
  CreateInvoiceRequest,
  UpdateInvoiceRequest,
  ListInvoicesQuery,
} from './types/invoicesTypes';
export { INVOICE_STATUS, type InvoiceStatus } from './constants/invoicesConstants';
