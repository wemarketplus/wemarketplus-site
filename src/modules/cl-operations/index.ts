export { ClOperationsPage } from './pages/ClOperationsPage';
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
export type { OpsListParams } from './api/clOperationsApi';
// The property-operations vocabulary and its display maps. Exported because the
// CommunityLink dashboards and My Queue count and label the same unit statuses,
// ticket priorities and task states this module owns — they must read the enums
// the operations screens write, not a private copy.
export {
  APARTMENT_STATUS,
  HOUSEKEEPING_STATUS,
  MAINTENANCE_STATUS,
  MAKE_READY_CATEGORY,
  MAKE_READY_STATUS,
  TICKET_PRIORITY,
  type ApartmentStatus,
  type HousekeepingStatus,
  type MaintenanceStatus,
  type MakeReadyCategory,
  type MakeReadyStatus,
  type TicketPriority,
} from './constants/clOperationsApiConstants';
export {
  APARTMENT_STATUS_LABELS,
  APARTMENT_STATUS_PILL,
  HOUSEKEEPING_STATUS_LABELS,
  HOUSEKEEPING_STATUS_PILL,
  MAINTENANCE_STATUS_LABELS,
  MAINTENANCE_STATUS_PILL,
  MAKE_READY_STATUS_LABELS,
  MAKE_READY_STATUS_PILL,
  TICKET_PRIORITY_LABELS,
  TICKET_PRIORITY_PILL,
} from './constants/clOperationsConstants';
export type {
  ClApartmentRecord,
  ClCommunityRecord,
  ClHousekeepingTaskRecord,
  ClMaintenanceTicketRecord,
  ClMakeReadyTaskRecord,
} from './types/clOperationsApiTypes';
export { occupancyRate } from './utils/occupancy';
export { toApartment } from './utils/clOperationsMappers';
