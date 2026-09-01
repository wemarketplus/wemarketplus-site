export { ClOutreachPage } from './pages/ClOutreachPage';
export { default as clOutreachReducer } from './store/clOutreachSlice';
export {
  clOutreachApi,
  useListClVisitsQuery,
  useCreateClVisitMutation,
  useScheduleClVisitMutation,
  useUpdateClVisitMutation,
  useDeleteClVisitMutation,
  useListClTasksQuery,
  useCreateClTaskMutation,
  useUpdateClTaskMutation,
  useDeleteClTaskMutation,
} from './api/clOutreachApi';
export {
  CL_TASK_STATUS,
  TICKET_PRIORITY,
  type ClTaskStatus,
  type TicketPriority,
} from './constants/clOutreachApiConstants';
export type {
  ClTaskRecord,
  CreateClTaskRequest,
  ClOutreachVisitRecord,
  CreateClOutreachVisitRequest,
} from './types/clOutreachApiTypes';
// The visit-type vocabulary, shared with the CommunityLink calendar so a visit
// scheduled there and one logged here offer (and label) the same buckets.
export {
  VISIT_TYPE,
  VISIT_TYPE_OPTIONS,
  VISIT_TYPE_LABELS,
  visitTypeLabel,
  type VisitType,
} from './constants/clOutreachConstants';
