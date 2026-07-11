export { ClOutreachPage } from './pages/ClOutreachPage';
export { default as clOutreachReducer } from './store/clOutreachSlice';
export {
  clOutreachApi,
  useListClVisitsQuery,
  useCreateClVisitMutation,
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
export type { ClTaskRecord, CreateClTaskRequest } from './types/clOutreachApiTypes';
