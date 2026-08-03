import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload, PaginationParams } from '@/shared/types';
import type {
  CreateTenantRequest,
  ImportResult,
  InviteRecord,
  TenantRecord,
} from '../types/adminTypes';

// Platform admin — wemarketplus-backend tenants, invites (admin/owner only),
// plus bulk data-transfer import. Export/template downloads live in
// utils/dataTransferUrls (binary downloads, not JSON calls).
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const adminApi = createApi({
  reducerPath: 'adminApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['Tenant', 'Invite'],
  endpoints: (build) => ({
    listTenants: build.query<PaginatedPayload<TenantRecord>, PaginationParams | void>({
      query: (p) => ({ url: '/tenants', params: p ?? undefined }),
      transformResponse: list<TenantRecord>,
      providesTags: ['Tenant'],
    }),
    getTenant: build.query<TenantRecord, string>({
      query: (id) => ({ url: `/tenants/${id}` }),
      transformResponse: env<TenantRecord>,
      providesTags: ['Tenant'],
    }),
    createTenant: build.mutation<TenantRecord, CreateTenantRequest>({
      query: (body) => ({ url: '/tenants', method: 'POST', body }),
      transformResponse: env<TenantRecord>,
      invalidatesTags: ['Tenant'],
    }),
    updateTenant: build.mutation<TenantRecord, { id: string; patch: Partial<CreateTenantRequest> }>({
      query: ({ id, patch }) => ({ url: `/tenants/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<TenantRecord>,
      invalidatesTags: ['Tenant'],
    }),
    deleteTenant: build.mutation<void, string>({
      query: (id) => ({ url: `/tenants/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Tenant'],
    }),
    listInvites: build.query<PaginatedPayload<InviteRecord>, PaginationParams | void>({
      query: (p) => ({ url: '/invites', params: p ?? undefined }),
      transformResponse: list<InviteRecord>,
      providesTags: ['Invite'],
    }),
    createInvite: build.mutation<InviteRecord & { token?: string }, { userId: string }>({
      query: (body) => ({ url: '/invites', method: 'POST', body }),
      transformResponse: env<InviteRecord & { token?: string }>,
      invalidatesTags: ['Invite'],
    }),
    // Bulk data transfer (data-transfer.controller). Import is JSON rows;
    // exports/templates are binary downloads handled by the URL helpers below.
    importData: build.mutation<ImportResult, { type: string; rows: Record<string, unknown>[]; batch?: number; totalBatches?: number }>({
      query: ({ type, ...body }) => ({ url: `/import/${type}`, method: 'POST', body }),
      transformResponse: env<ImportResult>,
    }),
  }),
});

export const {
  useListTenantsQuery,
  useGetTenantQuery,
  useCreateTenantMutation,
  useUpdateTenantMutation,
  useDeleteTenantMutation,
  useListInvitesQuery,
  useCreateInviteMutation,
  useImportDataMutation,
} = adminApi;
