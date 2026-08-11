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
export type {
  UserRecord,
  CalendarColorRecord,
  CreateUserRequest,
  UpdateUserRequest,
  UpdateOwnProfileRequest,
  SeatUsage,
} from './types/usersTypes';
