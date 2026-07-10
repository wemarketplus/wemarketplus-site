import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type { TenantProfile, UpdateMyTenantRequest } from '../types/tenantTypes';

// Settings owns the self-service tenant (organization) profile endpoints:
//   GET   /tenants/me  -> the caller's own tenant (TenantResponseDto)
//   PATCH /tenants/me  -> update profile fields (name, city, state, phone)
// Both are gated to Admin/Owner on the backend and scoped to the caller's
// tenantId — no arbitrary id is ever sent from the client.
//
// Other tabs reuse their owning module's slice:
//   - Profile      -> @/modules/users (PATCH /users/me)
//   - Integrations -> @/modules/integrations (GET /drive/status)
//   - Security     -> @/modules/auth
export const settingsApi = createApi({
  reducerPath: 'settingsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['MyTenant'],
  endpoints: (build) => ({
    getMyTenant: build.query<TenantProfile, void>({
      query: () => ({ url: '/tenants/me' }),
      transformResponse: (res: ApiEnvelope<TenantProfile>) => res.data,
      providesTags: ['MyTenant'],
    }),
    updateMyTenant: build.mutation<TenantProfile, UpdateMyTenantRequest>({
      query: (patch) => ({ url: '/tenants/me', method: 'PATCH', body: patch }),
      transformResponse: (res: ApiEnvelope<TenantProfile>) => res.data,
      invalidatesTags: ['MyTenant'],
    }),
  }),
});

export const { useGetMyTenantQuery, useUpdateMyTenantMutation } = settingsApi;
