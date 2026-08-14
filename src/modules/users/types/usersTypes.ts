import type { Role } from '@/shared/rbac';
import type { ID, ISODateString, PaginationParams } from '@/shared/types';
import type { EditUserFormValues, NewUserFormValues } from '../schema/usersSchema';

// Mirrors wemarketplus-backend/src/users/dto/user-response.dto.ts.
export interface UserRecord {
  id: ID;
  tenantId: ID;
  email: string;
  firstName: string;
  lastName: string;
  role: Role;
  phone: string | null;
  avatarUrl: string | null;
  // The user's chosen shared-calendar colour ('#rrggbb'), or null when they
  // haven't chosen and the UI derives one from the id.
  calendarColor: string | null;
  isActive: boolean;
  createdAt: ISODateString;
  updatedAt: ISODateString;
  /** Set when this user holds a tenant-defined job title. */
  customRoleId?: string | null;
}

// GET /users/calendar-colors — wemarketplus-backend/src/users/dto/calendar-color.dto.ts.
// Open to every authenticated role (GET /users is staff-only), because the
// shared calendar has to colour colleagues' rows for field personas too. It
// carries nothing but the pair below — no name, email, role or account state.
export interface CalendarColorRecord {
  userId: ID;
  calendarColor: string | null;
}

/**
 * GET /users/assignable — id + name only, for assignment pickers.
 *
 * Deliberately not UserRecord: the full user list is Admin/Owner/Manager-only, and
 * a field persona picking which colleague gives a tour needs a name and nothing
 * else. Mirrors the backend StaffOptionDto.
 */
export interface StaffOptionRecord {
  id: ID;
  name: string;
}

// POST /users body — wemarketplus-backend/src/users/dto/create-user.dto.ts.
export interface CreateUserRequest {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  role?: Role;
  /**
   * A tenant-defined job title to give this user (custom_roles.id) instead of a bare
   * role. When set, the backend FORCES `role` to that custom role's baseRole, so the
   * enforced permissions and the job title can never disagree.
   */
  customRoleId?: string | null;
}

// PATCH /users/:id body — wemarketplus-backend/src/users/dto/update-user.dto.ts.
export interface UpdateUserRequest {
  email?: string;
  firstName?: string;
  lastName?: string;
  role?: Role;
  // Enable/disable (deactivate/reactivate) the account. The backend guards
  // self-disable and the last privileged (Owner/Admin) account.
  isActive?: boolean;
  /**
   * A tenant-defined job title to give this user (custom_roles.id) instead of a bare
   * role. When set, the backend FORCES `role` to that custom role's baseRole, so the
   * enforced permissions and the job title can never disagree.
   */
  customRoleId?: string | null;
}

// PATCH /users/me body — wemarketplus-backend/src/users/dto/update-own-profile.dto.ts.
// The self-service route: it always targets the caller (the backend reads the id
// from the JWT), and deliberately accepts NO id, role, tenant or active-state
// field — sending one is a 400, not a silent no-op.
export interface UpdateOwnProfileRequest {
  email?: string;
  firstName?: string;
  lastName?: string;
  phone?: string;
  // One of CALENDAR_PALETTE's hex values, or null to go back to the colour
  // derived from the user id. `null` is a real instruction here, not "unset".
  calendarColor?: string | null;
}

// POST /users/:id/reset-password — admin resets another user's password.
// Backend generates a temporary password (no request body) and returns it.
export interface AdminResetPasswordResponse {
  temporaryPassword: string;
}

export type ListUsersQuery = PaginationParams;

export interface UsersUiState {
  search: string;
  selectedRole: Role | 'all';
}

// --- Component prop types ---

export interface AddUserModalProps {
  open: boolean;
  isSaving: boolean;
  // API-level failure from the last submit (seat limit, duplicate email,
  // permission errors) — rendered verbatim in the form's inline error box.
  submitError: string | null;
  onClose: () => void;
  // Returns true when the create succeeded, so the form can reset.
  onSubmit: (values: NewUserFormValues) => Promise<boolean>;
}

export interface EditUserModalProps {
  // The user being edited; null while the modal is closed. Drives the form's
  // initial values (name, role, active status).
  user: UserRecord | null;
  open: boolean;
  isSaving: boolean;
  // API-level failure from the last submit (last-admin, can't-disable-self,
  // permission errors) — rendered verbatim in the form's inline error box.
  submitError: string | null;
  onClose: () => void;
  // Returns true when the update succeeded, so the modal can close.
  onSubmit: (values: EditUserFormValues) => Promise<boolean>;
}

/**
 * Seat utilisation for the tenant (GET /users/seats).
 *
 * Mirrors wemarketplus-backend/src/users/dto/seat-usage.dto.ts. `allowed` and
 * `remaining` are nullable because an unrecognised plan is treated as UNCAPPED
 * server-side — null means "no cap known", never "zero seats".
 */
export interface SeatUsage {
  planName: string | null;
  allowed: number | null;
  used: number;
  remaining: number | null;
  /** False in dev/test, where the limit is displayed but not enforced. */
  enforced: boolean;
}
