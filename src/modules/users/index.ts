// Public surface of the users module. Internals stay private.
export { UsersPage } from './pages/UsersPage';
export { default as usersReducer } from './store/usersSlice';
export {
  usersApi,
  useListUsersQuery,
  useListCalendarColorsQuery,
  useUpdateOwnProfileMutation,
  useGetSeatUsageQuery,
} from './api/usersApi';
// Role-aware "who is doing this?" picker data. Shared by the tour scheduler and
// the CommunityLink calendar; see the hook for why it degrades to "Me" instead
// of 403-ing for the sales roles.
export {
  useTenantStaffOptions,
  type TenantStaffOptions,
} from './hooks/useTenantStaffOptions';
export type {
  UserRecord,
  CalendarColorRecord,
  CreateUserRequest,
  UpdateUserRequest,
  UpdateOwnProfileRequest,
  SeatUsage,
} from './types/usersTypes';
