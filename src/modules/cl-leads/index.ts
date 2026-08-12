export { LeadsPage } from './pages/LeadsPage';
export { ActivityNotesPage } from './pages/ActivityNotesPage';
export {
  leadsApi,
  useListClLeadsQuery,
  useGetClLeadQuery,
  useCreateClLeadMutation,
  useUpdateClLeadMutation,
  useDeleteClLeadMutation,
  useListClLeadNotesQuery,
  useCreateClLeadNoteMutation,
} from './api/leadsApi';
export type { ClLeadListParams } from './api/leadsApi';
// The backend lead vocabulary. Exported because the CommunityLink dashboards,
// calendar and Daily Task all classify leads by stage/urgency and must use the
// same enums the pipeline writes — a second copy is how "hot" quietly comes to
// mean two different things on two screens.
export {
  CL_CARE_LEVEL,
  CL_LEAD_STAGE,
  CL_URGENCY,
  type ClCareLevel,
  type ClLeadStage,
  type ClUrgency,
} from './constants/clLeadApiConstants';
export type {
  ClLeadRecord,
  ClLeadNoteRecord,
  CreateClLeadRequest,
  UpdateClLeadRequest,
} from './types/clLeadApiTypes';
