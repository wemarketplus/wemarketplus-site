// `modules/permissions` is the *admin CRUD shell* over permission records.
// It is intentionally distinct from `shared/rbac`, which is the app-wide
// *enforcement mechanism* (RoleGate, useRole, Role constants). Do not blur
// this boundary — UI gating belongs in `shared/rbac`, admin management of
// permission records belongs here.
export { PermissionsPage } from './pages/PermissionsPage';
export { default as permissionsReducer } from './store/permissionsSlice';
