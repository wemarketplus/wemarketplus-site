// DEPRECATED — NOT NEEDED, PENDING REMOVAL.
// Applications is one of the three Grants modules (Funding / Applications /
// Agreements). Removed from the sidebar on 2026-08-06 per the product owner;
// the whole Grants domain is slated to be removed/purged from FE and BE. The
// code is kept only so the section can be restored quickly if it turns out to
// be needed. Do NOT build new features on this module or wire it into new
// screens.
//
// Grant-CRM applications — full CRUD UI on the shared entity kit.
export { ApplicationsPage } from './pages/ApplicationsPage';
export {
  applicationsApi,
  useListApplicationsQuery,
  useGetApplicationQuery,
  useCreateApplicationMutation,
  useUpdateApplicationMutation,
  useDeleteApplicationMutation,
} from './api/applicationsApi';
export type {
  ApplicationRecord,
  CreateApplicationRequest,
  UpdateApplicationRequest,
  ListApplicationsQuery,
} from './types/applicationsTypes';
export { APPLICATION_STATUS, type ApplicationStatus } from './constants/applicationsConstants';
