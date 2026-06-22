// Grant-CRM applications — API-only module (no page UI yet).
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
