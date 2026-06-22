import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type { PermissionsView, UpdatePermissionRequest } from '../types/permissionsApiTypes';

// Backend permission matrix — wemarketplus-backend/src/permissions.
//   GET /permissions  -> { permissions, locked } (PermissionsView)
//   PUT /permissions  -> PermissionsView (super_admin only)
// NOTE: this is the grant-CRM permission-key matrix (e.g. create_wibs_companies),
// a different model from the descriptive role-capability guide the
// PermissionsPage currently renders. The API is wired for future use; the page
// stays as-is for now.
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
      invalidatesTags: ['Permissions'],
    }),
  }),
});

export const { useGetPermissionsQuery, useUpdatePermissionMutation } = permissionsApi;
