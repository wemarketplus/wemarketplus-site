import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload } from '@/shared/types';
import { PROSPECTS_TAGS } from '../constants/prospectsConstants';
import type {
  CreateProspectRequest,
  ListProspectsQuery,
  ProspectRecord,
  UpdateProspectRequest,
  ReengagementRow,
} from '../types/prospectsTypes';

// Verified against wemarketplus-backend/src/prospects/prospects.controller.ts:
//   GET    /prospects?page&limit&stage&assignedTo -> PaginatedResult<ProspectResponseDto>
//   GET    /prospects/:id
//   POST   /prospects                              body:CreateProspectDto
//   PATCH  /prospects/:id                          body:UpdateProspectDto
//   DELETE /prospects/:id                          (admin/owner/manager only)
export const prospectsApi = createApi({
  reducerPath: 'prospectsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: [PROSPECTS_TAGS.List, PROSPECTS_TAGS.Detail],
  endpoints: (build) => ({
    listProspects: build.query<PaginatedPayload<ProspectRecord>, ListProspectsQuery | void>({
      query: (params) => ({ url: '/prospects', params: params ?? undefined }),
      transformResponse: (res: ApiEnvelope<PaginatedPayload<ProspectRecord>>) => res.data,
      providesTags: (result) =>
        result
          ? [
              ...result.data.map((p) => ({ type: PROSPECTS_TAGS.Detail, id: p.id }) as const),
              { type: PROSPECTS_TAGS.List, id: 'PARTIAL-LIST' },
            ]
          : [{ type: PROSPECTS_TAGS.List, id: 'PARTIAL-LIST' }],
    }),
    /**
     * The re-engagement queue: open pipeline rows quiet past the 30-day
     * threshold, longest-quiet first. Inactivity is derived server-side from
     * notes, completed visits, completed jobs and stage changes — never from
     * `updatedAt`, which any field edit would reset.
     */
    listReengagement: build.query<
      ReengagementRow[],
      { limit?: number; assignedTo?: string } | void
    >({
      query: (params) => ({
        url: '/prospects/re-engagement',
        params: params ?? undefined,
      }),
      transformResponse: (res: ApiEnvelope<ReengagementRow[]>) => res.data,
      providesTags: [{ type: PROSPECTS_TAGS.List, id: 'REENGAGEMENT' }],
    }),
    getProspect: build.query<ProspectRecord, string>({
      query: (id) => ({ url: `/prospects/${id}` }),
      transformResponse: (res: ApiEnvelope<ProspectRecord>) => res.data,
      providesTags: (_r, _e, id) => [{ type: PROSPECTS_TAGS.Detail, id }],
    }),
    createProspect: build.mutation<ProspectRecord, CreateProspectRequest>({
      query: (body) => ({ url: '/prospects', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<ProspectRecord>) => res.data,
      invalidatesTags: [{ type: PROSPECTS_TAGS.List, id: 'PARTIAL-LIST' }],
    }),
    updateProspect: build.mutation<ProspectRecord, { id: string; patch: UpdateProspectRequest }>({
      query: ({ id, patch }) => ({ url: `/prospects/${id}`, method: 'PATCH', body: patch }),
      transformResponse: (res: ApiEnvelope<ProspectRecord>) => res.data,
      invalidatesTags: (_r, _e, { id }) => [
        { type: PROSPECTS_TAGS.Detail, id },
        { type: PROSPECTS_TAGS.List, id: 'PARTIAL-LIST' },
      ],
    }),
    deleteProspect: build.mutation<void, string>({
      query: (id) => ({ url: `/prospects/${id}`, method: 'DELETE' }),
      invalidatesTags: (_r, _e, id) => [
        { type: PROSPECTS_TAGS.Detail, id },
        { type: PROSPECTS_TAGS.List, id: 'PARTIAL-LIST' },
      ],
    }),
  }),
});

export const {
  useListReengagementQuery,
  useListProspectsQuery,
  useGetProspectQuery,
  useCreateProspectMutation,
  useUpdateProspectMutation,
  useDeleteProspectMutation,
} = prospectsApi;
