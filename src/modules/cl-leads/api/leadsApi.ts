import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload, PaginationParams } from '@/shared/types';
import type {
  ClLeadNoteRecord,
  ClLeadRecord,
  CreateClLeadNoteRequest,
  CreateClLeadRequest,
  UpdateClLeadRequest,
} from '../types/clLeadApiTypes';

// Server-side list params: pagination + optional free-text search + stage/urgency
// equality filters (backend ClListQueryDto). Blank values are stripped before the
// request so the DTO never sees empty strings.
export interface ClLeadListParams extends PaginationParams {
  search?: string;
  stage?: string;
  urgency?: string;
}

function cleanParams(params?: ClLeadListParams): Record<string, string | number> | undefined {
  if (!params) return undefined;
  const out: Record<string, string | number> = {};
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== '') out[key] = value;
  }
  return Object.keys(out).length ? out : undefined;
}

// CommunityLink leads — wemarketplus-backend/src/communitylink (cl/leads, cl/lead-notes).
//   GET/POST/GET:id/PATCH/DELETE /cl/leads; GET /cl/lead-notes.
export const leadsApi = createApi({
  reducerPath: 'clLeadsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['ClLead', 'ClLeadNote'],
  endpoints: (build) => ({
    listClLeads: build.query<PaginatedPayload<ClLeadRecord>, ClLeadListParams | void>({
      query: (params) => ({ url: '/cl/leads', params: cleanParams(params ?? undefined) }),
      transformResponse: (res: ApiEnvelope<PaginatedPayload<ClLeadRecord>>) => res.data,
      providesTags: ['ClLead'],
    }),
    getClLead: build.query<ClLeadRecord, string>({
      query: (id) => ({ url: `/cl/leads/${id}` }),
      transformResponse: (res: ApiEnvelope<ClLeadRecord>) => res.data,
      providesTags: ['ClLead'],
    }),
    createClLead: build.mutation<ClLeadRecord, CreateClLeadRequest>({
      query: (body) => ({ url: '/cl/leads', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<ClLeadRecord>) => res.data,
      invalidatesTags: ['ClLead'],
    }),
    updateClLead: build.mutation<ClLeadRecord, { id: string; patch: UpdateClLeadRequest }>({
      query: ({ id, patch }) => ({ url: `/cl/leads/${id}`, method: 'PATCH', body: patch }),
      transformResponse: (res: ApiEnvelope<ClLeadRecord>) => res.data,
      invalidatesTags: ['ClLead'],
    }),
    deleteClLead: build.mutation<void, string>({
      query: (id) => ({ url: `/cl/leads/${id}`, method: 'DELETE' }),
      invalidatesTags: ['ClLead'],
    }),
    listClLeadNotes: build.query<PaginatedPayload<ClLeadNoteRecord>, PaginationParams | void>({
      query: (params) => ({ url: '/cl/lead-notes', params: params ?? undefined }),
      transformResponse: (res: ApiEnvelope<PaginatedPayload<ClLeadNoteRecord>>) => res.data,
      providesTags: ['ClLeadNote'],
    }),
    createClLeadNote: build.mutation<ClLeadNoteRecord, CreateClLeadNoteRequest>({
      query: (body) => ({ url: '/cl/lead-notes', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<ClLeadNoteRecord>) => res.data,
      invalidatesTags: ['ClLeadNote'],
    }),
  }),
});

export const {
  useListClLeadsQuery,
  useGetClLeadQuery,
  useCreateClLeadMutation,
  useUpdateClLeadMutation,
  useDeleteClLeadMutation,
  useListClLeadNotesQuery,
  useCreateClLeadNoteMutation,
} = leadsApi;
