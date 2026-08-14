export { ClOperationsPage } from './pages/ClOperationsPage';
/**
 * The assignable-staff picker source, shared with any board that assigns work.
 * Exported so the CommunityLink Tasks module drives its "Assigned to" field and
 * its "Assigned to me" filter from the SAME `/users/assignable` projection the
 * operations boards use — two staff lists that could disagree about who works
 * here is how an assignee silently vanishes from one screen but not another.
 */
export { useOpsStaff } from './hooks/useOpsStaff';
export { OccupancyOverviewPage } from './pages/OccupancyOverviewPage';
export { default as clOperationsReducer } from './store/clOperationsSlice';
export {
  clOperationsApi,
  useListClCommunitiesQuery,
  useCreateClCommunityMutation,
  useListClApartmentsQuery,
  useCreateClApartmentMutation,
  useUpdateClApartmentMutation,
  useDeleteClApartmentMutation,
  useListClMakeReadyQuery,
  useCreateClMakeReadyMutation,
  useUpdateClMakeReadyMutation,
  useDeleteClMakeReadyMutation,
  useListClMaintenanceQuery,
  useCreateClMaintenanceMutation,
  useUpdateClMaintenanceMutation,
  useDeleteClMaintenanceMutation,
  useListClHousekeepingQuery,
  useCreateClHousekeepingMutation,
  useUpdateClHousekeepingMutation,
  useDeleteClHousekeepingMutation,
} from './api/clOperationsApi';
// The operations vocabulary, so a surface outside this module renders the same
// labels and colours the operations tables do rather than growing a second set.
// Consumers: the Executive Dashboard's Unit Status card (apartment status) and
// "My Queue" (@/modules/daily-queue), which lists the same three kinds of work
// order and must not invent its own word for "in progress".
export {
  APARTMENT_STATUS_LABELS,
  APARTMENT_STATUS_PILL,
  MAINTENANCE_STATUS_LABELS,
  MAINTENANCE_STATUS_PILL,
  MAKE_READY_STATUS_LABELS,
  MAKE_READY_STATUS_PILL,
  HOUSEKEEPING_STATUS_LABELS,
  HOUSEKEEPING_STATUS_PILL,
  TICKET_PRIORITY_LABELS,
  TICKET_PRIORITY_PILL,
} from './constants/clOperationsConstants';
export { APARTMENT_STATUS } from './constants/clOperationsApiConstants';
export type { ApartmentStatus as ClApartmentStatus } from './constants/clOperationsApiConstants';
