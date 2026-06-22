// Platform admin (tenants + invites) — API-only module (no page UI yet).
export {
  adminApi,
  useListTenantsQuery,
  useGetTenantQuery,
  useCreateTenantMutation,
  useUpdateTenantMutation,
  useDeleteTenantMutation,
  useListInvitesQuery,
  useCreateInviteMutation,
  useImportDataMutation,
  useImportWibsCsvMutation,
} from './api/adminApi';
export {
  exportCsvUrl,
  exportXlsxUrl,
  importTemplateCsvUrl,
  importTemplateXlsxUrl,
} from './utils/dataTransferUrls';
export type {
  TenantRecord,
  CreateTenantRequest,
  InviteRecord,
  ImportDataRequest,
} from './types/adminTypes';
