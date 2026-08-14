// Public surface of the users module. Internals stay private.
export { UsersPage } from './pages/UsersPage';
export { default as usersReducer } from './store/usersSlice';
/**
 * The invite flow (POST /users + the optional POST /invites), exported as the
 * pair it is: the hook owns the mutations and the modal is presentational.
 *
 * Settings reuses BOTH so its "+ Invite User" button is the same invite the Team
 * page performs — seat-limit errors, custom-role picker, temp-password
 * generation and list invalidation included. Re-implementing an invite form
 * beside this one is how the two would drift.
 */
export { useAddUser } from './hooks/useAddUser';
export { AddUserModal } from './components/AddUserModal';
export {
  usersApi,
  useListUsersQuery,
  useListCalendarColorsQuery,
  useListAssignableStaffQuery,
  useUpdateOwnProfileMutation,
  useGetSeatUsageQuery,
} from './api/usersApi';
export type {
  UserRecord,
  CalendarColorRecord,
  StaffOptionRecord,
  CreateUserRequest,
  UpdateUserRequest,
  UpdateOwnProfileRequest,
  SeatUsage,
} from './types/usersTypes';
