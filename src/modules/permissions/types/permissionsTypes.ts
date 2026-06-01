import type { Role } from '@/shared/rbac';

// `shared/rbac` is the enforcement layer; `modules/permissions` is the admin
// CRUD shell. Today the backend is role-based with no Permission entity, so
// this module renders a read-only matrix of role capabilities. When the
// backend ships a permission table, swap this for the real DTO.
export interface RoleCapability {
  role: Role;
  description: string;
  capabilities: readonly string[];
}

export interface PermissionsUiState {
  _placeholder: true;
}
