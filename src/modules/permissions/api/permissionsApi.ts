import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type { CustomRole } from '@/shared/rbac';
import type { PermissionsView, UpdatePermissionRequest } from '../types/permissionsApiTypes';
import type {
  CreateCustomRoleRequest,
  UpdateCustomRoleRequest,
} from '../types/permissionsApiTypes';

// Backend permission matrix — wemarketplus-backend/src/permissions.
//   GET /permissions  -> { permissions, locked, canEdit, restricted }
//   PUT /permissions  -> the same shape (tenant-admin tier: super admin/admin/owner)
// Both responses are ACTOR-SCOPED: `canEdit` and `restricted` describe the caller,
// so the UI renders what the API will accept rather than re-deriving the policy.
// This is the grant-CRM permission-key matrix (e.g. create_wibs_companies).
// The PermissionsPage renders it as a live, editable RBAC grid.
export const permissionsApi = createApi({
  reducerPath: 'permissionsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['Permissions', 'CustomRoles'],
  endpoints: (build) => ({
    getPermissions: build.query<PermissionsView, void>({
      query: () => ({ url: '/permissions' }),
      transformResponse: (res: ApiEnvelope<PermissionsView>) => res.data,
      providesTags: ['Permissions'],
    }),
    /**
     * Admin → Manage Roles. Lives in this slice rather than its own because it is
     * the same screen and the same audience as the permission matrix, and a second
     * createApi would need its own store registration for two extra endpoints.
     *
     * Every route here answers 402 UPGRADE_REQUIRED on a Pro tenant
     * (@RequireFeature("custom_roles")) and 403 for anyone below Admin/Owner.
     */
    listCustomRoles: build.query<CustomRole[], void>({
      query: () => ({ url: '/custom-roles' }),
      transformResponse: (res: ApiEnvelope<CustomRole[]>) => res.data,
      providesTags: ['CustomRoles'],
    }),
    createCustomRole: build.mutation<CustomRole, CreateCustomRoleRequest>({
      query: (body) => ({ url: '/custom-roles', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<CustomRole>) => res.data,
      invalidatesTags: ['CustomRoles'],
    }),
    updateCustomRole: build.mutation<CustomRole, UpdateCustomRoleRequest>({
      query: ({ id, patch }) => ({
        url: `/custom-roles/${id}`,
        method: 'PATCH',
        body: patch,
      }),
      transformResponse: (res: ApiEnvelope<CustomRole>) => res.data,
      invalidatesTags: ['CustomRoles'],
    }),
    deleteCustomRole: build.mutation<void, string>({
      query: (id) => ({ url: `/custom-roles/${id}`, method: 'DELETE' }),
      invalidatesTags: ['CustomRoles'],
    }),
    updatePermission: build.mutation<PermissionsView, UpdatePermissionRequest>({
      query: (body) => ({ url: '/permissions', method: 'PUT', body }),
      transformResponse: (res: ApiEnvelope<PermissionsView>) => res.data,
      // Optimistically flip the toggled cell in the cached GET /permissions view
      // so the checkbox responds instantly; roll the patch back if the PUT fails
      // (locked cell -> 400, non-super-admin -> 403). The server's authoritative
      // view replaces the cache on success.
      async onQueryStarted({ permission, role, value }, { dispatch, queryFulfilled }) {
        const patch = dispatch(
          permissionsApi.util.updateQueryData('getPermissions', undefined, (draft) => {
            const cell = draft.permissions[permission];
            if (cell) cell[role] = value;
          }),
        );
        try {
          const { data } = await queryFulfilled;
          dispatch(
            permissionsApi.util.updateQueryData('getPermissions', undefined, (draft) => {
              draft.permissions = data.permissions;
              draft.locked = data.locked;
              // Carry the actor-scoped fields too, so the grid never drifts from
              // what the server just said this actor may change.
              draft.canEdit = data.canEdit;
              draft.restricted = data.restricted;
            }),
          );
        } catch {
          patch.undo();
        }
      },
    }),
  }),
});

export const {
  useGetPermissionsQuery,
  useUpdatePermissionMutation,
  useListCustomRolesQuery,
  useCreateCustomRoleMutation,
  useUpdateCustomRoleMutation,
  useDeleteCustomRoleMutation,
} = permissionsApi;
