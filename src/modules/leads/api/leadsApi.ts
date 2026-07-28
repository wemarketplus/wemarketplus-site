import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload } from '@/shared/types';
import { LEADS_TAGS } from '../constants/leadsConstants';
import type {
  ConvertLeadRequest,
  CreateLeadRequest,
  DisqualifyLeadRequest,
  LeadConversionResult,
  LeadRecord,
  ListLeadsQuery,
  UpdateLeadRequest,
} from '../types/leadsTypes';

// Verified against wemarketplus-backend/src/leads/leads.controller.ts:
//   GET    /hl/leads?page&limit&search&status&sourceType&assignedTo
//   GET    /hl/leads/:id
//   POST   /hl/leads
//   PATCH  /hl/leads/:id
//   POST   /hl/leads/:id/convert      -> { lead, pipeline, companyId, contactId }
//   POST   /hl/leads/:id/disqualify
//   DELETE /hl/leads/:id              (admin/owner/manager only)
// NOTE: the route prefix is /hl/leads — /contacts and /leads without the prefix
// belong to the Grant-CRM and CommunityLink surfaces respectively.
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const leadsApi = createApi({
  reducerPath: 'leadsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: [LEADS_TAGS.List, LEADS_TAGS.Detail],
  endpoints: (build) => ({
    listLeads: build.query<PaginatedPayload<LeadRecord>, ListLeadsQuery | void>({
      query: (params) => ({ url: '/hl/leads', params: params ?? undefined }),
      transformResponse: list<LeadRecord>,
      providesTags: (result) =>
        result
          ? [
              ...result.data.map(
                (l) => ({ type: LEADS_TAGS.Detail, id: l.id }) as const,
              ),
              { type: LEADS_TAGS.List, id: 'PARTIAL-LIST' },
            ]
          : [{ type: LEADS_TAGS.List, id: 'PARTIAL-LIST' }],
    }),
    getLead: build.query<LeadRecord, string>({
      query: (id) => ({ url: `/hl/leads/${id}` }),
      transformResponse: env<LeadRecord>,
      providesTags: (_r, _e, id) => [{ type: LEADS_TAGS.Detail, id }],
    }),
    createLead: build.mutation<LeadRecord, CreateLeadRequest>({
      query: (body) => ({ url: '/hl/leads', method: 'POST', body }),
      transformResponse: env<LeadRecord>,
      invalidatesTags: [{ type: LEADS_TAGS.List, id: 'PARTIAL-LIST' }],
    }),
    updateLead: build.mutation<
      LeadRecord,
      { id: string; patch: UpdateLeadRequest }
    >({
      query: ({ id, patch }) => ({
        url: `/hl/leads/${id}`,
        method: 'PATCH',
        body: patch,
      }),
      transformResponse: env<LeadRecord>,
      invalidatesTags: (_r, _e, { id }) => [
        { type: LEADS_TAGS.Detail, id },
        { type: LEADS_TAGS.List, id: 'PARTIAL-LIST' },
      ],
    }),
    convertLead: build.mutation<
      LeadConversionResult,
      { id: string; body?: ConvertLeadRequest }
    >({
      query: ({ id, body }) => ({
        url: `/hl/leads/${id}/convert`,
        method: 'POST',
        body: body ?? {},
      }),
      transformResponse: env<LeadConversionResult>,
      invalidatesTags: (_r, _e, { id }) => [
        { type: LEADS_TAGS.Detail, id },
        { type: LEADS_TAGS.List, id: 'PARTIAL-LIST' },
      ],
    }),
    disqualifyLead: build.mutation<
      LeadRecord,
      { id: string; body: DisqualifyLeadRequest }
    >({
      query: ({ id, body }) => ({
        url: `/hl/leads/${id}/disqualify`,
        method: 'POST',
        body,
      }),
      transformResponse: env<LeadRecord>,
      invalidatesTags: (_r, _e, { id }) => [
        { type: LEADS_TAGS.Detail, id },
        { type: LEADS_TAGS.List, id: 'PARTIAL-LIST' },
      ],
    }),
    deleteLead: build.mutation<void, string>({
      query: (id) => ({ url: `/hl/leads/${id}`, method: 'DELETE' }),
      invalidatesTags: (_r, _e, id) => [
        { type: LEADS_TAGS.Detail, id },
        { type: LEADS_TAGS.List, id: 'PARTIAL-LIST' },
      ],
    }),
  }),
});

export const {
  useListLeadsQuery,
  useGetLeadQuery,
  useCreateLeadMutation,
  useUpdateLeadMutation,
  useConvertLeadMutation,
  useDisqualifyLeadMutation,
  useDeleteLeadMutation,
} = leadsApi;
