// Field execution surfaces for HospiceLink: visit verification (EVV) and mileage.
//
// Both were unreachable before this module existed — EVV had endpoints and written
// RTK hooks that no component consumed, and mileage had endpoints with no client at
// all. Both are sold at Max as "EVV/GPS mileage & compliance log", and the Nurse and
// Caregiver personas depend on them (their scoped views are mostly these screens
// plus Notes and Family communication).
export { EvvPage } from './pages/EvvPage';
export { MileagePage } from './pages/MileagePage';
export {
  mileageApi,
  useListMileageLogsQuery,
  useCreateMileageLogMutation,
  useUpdateMileageLogMutation,
  useDeleteMileageLogMutation,
  useGetTeamMileageSummaryQuery,
  useListExpenseReceiptsQuery,
  useUploadExpenseReceiptMutation,
} from './api/mileageApi';
export { AttachReceiptDialog } from './components/AttachReceiptDialog';
export { ReceiptFileButton } from './components/ReceiptFileButton';
export type {
  MileageLogRecord,
  CreateMileageLogRequest,
  UpdateMileageLogRequest,
  TeamMileageSummary,
  ExpenseReceiptRecord,
  UploadExpenseReceiptRequest,
} from './types/fieldTypes';
