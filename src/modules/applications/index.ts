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
