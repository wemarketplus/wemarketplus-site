export { ActivityPage } from './pages/ActivityPage';
// Shared record-level activity surfaces. Exported from `activity` rather than
// duplicated per module: the facility touch log and a prospect's team notes are
// the same list of notes filtered differently.
export { TouchLog } from './components/TouchLog';
export { LogInteractionModal } from './components/LogInteractionModal';
export { default as activityReducer } from './store/activitySlice';
export {
  activityApi,
  useListActivityFeedQuery,
  useListTasksQuery,
  useGetTaskQuery,
  useCreateTaskMutation,
  useUpdateTaskMutation,
  useDeleteTaskMutation,
  useListNotesQuery,
  useGetNoteQuery,
  useCreateNoteMutation,
  useUpdateNoteMutation,
  useListGoalsQuery,
  useGetGoalQuery,
  useCreateGoalMutation,
  useUpdateGoalMutation,
  useDeleteGoalMutation,
} from './api/activityApi';
