// `modules/permissions` is the *admin management surface* for the RBAC matrix.
// It renders the live, editable permission grid (GET/PUT /permissions) that the
// backend enforces via @RequirePermission guards. It is intentionally distinct
// from `shared/rbac`, which is the app-wide *enforcement mechanism* (RoleGate,
// useRole, Role constants). Do not blur this boundary — UI gating belongs in
// `shared/rbac`, admin management of the matrix belongs here.
export { PermissionsPage } from './pages/PermissionsPage';
export { default as permissionsReducer } from './store/permissionsSlice';
export {
  permissionsApi,
  useGetPermissionsQuery,
  useUpdatePermissionMutation,
  // Custom roles (Admin → Manage Roles). Exported for the Users module's role
  // pickers, which need the tenant's assignable job titles.
  useListCustomRolesQuery,
  useCreateCustomRoleMutation,
  useUpdateCustomRoleMutation,
  useDeleteCustomRoleMutation,
} from './api/permissionsApi';
export { ManageCustomRoles } from './components/ManageCustomRoles';
