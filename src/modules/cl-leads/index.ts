export { LeadsPage } from './pages/LeadsPage';
export { ActivityNotesPage } from './pages/ActivityNotesPage';
export { ResidentCareLogPage } from './pages/ResidentCareLogPage';
export {
  leadsApi,
  useListClLeadsQuery,
  useGetClLeadQuery,
  useCreateClLeadMutation,
  useUpdateClLeadMutation,
  useDeleteClLeadMutation,
  useListClLeadNotesQuery,
  useCreateClLeadNoteMutation,
  useListClResidentsQuery,
  useCreateClResidentMutation,
} from './api/leadsApi';
export type { ClLeadListParams, ClLeadNoteListParams } from './api/leadsApi';
// The backend lead vocabulary. Exported because the CommunityLink dashboards,
// calendar and Daily Task all classify leads by stage/urgency and must use the
// same enums the pipeline writes — a second copy is how "hot" quietly comes to
// mean two different things on two screens.
export {
  CL_CARE_LEVEL,
  CL_LEAD_STAGE,
  CL_URGENCY,
  CL_RESIDENT_NOTE_CATEGORY,
  CL_RESIDENT_NOTE_CATEGORY_LABELS,
  type ClCareLevel,
  type ClLeadStage,
  type ClUrgency,
  type ClResidentNoteCategory,
} from './constants/clLeadApiConstants';
export type {
  ClLeadRecord,
  ClLeadNoteRecord,
  ClResidentRecord,
  CreateClLeadNoteRequest,
  CreateClLeadRequest,
  CreateClResidentRequest,
  UpdateClLeadRequest,
} from './types/clLeadApiTypes';
