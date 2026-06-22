import type { Role } from '@/shared/rbac';
import type { ID, ISODateString, PaginationParams } from '@/shared/types';

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
