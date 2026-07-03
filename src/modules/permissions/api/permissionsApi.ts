import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type { PermissionsView, UpdatePermissionRequest } from '../types/permissionsApiTypes';

// Backend permission matrix — wemarketplus-backend/src/permissions.
//   GET /permissions  -> { permissions, locked } (PermissionsView)
//   PUT /permissions  -> PermissionsView (super_admin only)
// This is the grant-CRM permission-key matrix (e.g. create_wibs_companies).
// The PermissionsPage renders it as a live, editable RBAC grid.
export const permissionsApi = createApi({
  reducerPath: 'permissionsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['Permissions'],
  endpoints: (build) => ({
    getPermissions: build.query<PermissionsView, void>({
      query: () => ({ url: '/permissions' }),
      transformResponse: (res: ApiEnvelope<PermissionsView>) => res.data,
      providesTags: ['Permissions'],
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
            }),
          );
        } catch {
          patch.undo();
        }
      },
    }),
  }),
});

export const { useGetPermissionsQuery, useUpdatePermissionMutation } = permissionsApi;
