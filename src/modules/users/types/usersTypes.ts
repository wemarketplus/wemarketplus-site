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
  isActive: boolean;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

// POST /users body — wemarketplus-backend/src/users/dto/create-user.dto.ts.
export interface CreateUserRequest {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  role?: Role;
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
}

// PATCH /users/me body — wemarketplus-backend/src/users/dto/update-own-profile.dto.ts.
export interface UpdateOwnProfileRequest {
  email?: string;
  firstName?: string;
  lastName?: string;
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
