import type { Role } from '@/shared/rbac';
import type { ID, ISODateString, PaginationParams } from '@/shared/types';

// Mirrors wemarketplus-backend/src/users/dto/user-response.dto.ts.
export interface UserRecord {
  id: ID;
  email: string;
  firstName: string;
  lastName: string;
  role: Role;
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

export interface ListUsersQuery extends PaginationParams {}

export interface UsersUiState {
  search: string;
  selectedRole: Role | 'all';
}
