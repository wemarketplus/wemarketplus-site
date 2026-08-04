// Nurse rostering (the Gold "Smart scheduling" slot) plus the pre-existing territory
// views. NurseRosterPage is the real module; the territory heatmap stays available but
// is no longer the whole screen, since it never had a data layer.
export { SchedulingPage } from './pages/SchedulingPage';
export { NurseRosterPage } from './pages/NurseRosterPage';
export { default as schedulingReducer } from './store/schedulingSlice';
export {
  schedulingApi,
  useListShiftsQuery,
  useGetCoverageQuery,
  useCreateShiftMutation,
  useUpdateShiftMutation,
  useDeleteShiftMutation,
} from './api/schedulingApi';
export type {
  NurseShiftRecord,
  CoverageDay,
  CoverageResponse,
} from './types/schedulingTypes';
