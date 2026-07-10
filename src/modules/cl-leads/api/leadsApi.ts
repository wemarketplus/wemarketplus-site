import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload, PaginationParams } from '@/shared/types';
import type {
  ClLeadNoteRecord,
  ClLeadRecord,
  CreateClLeadRequest,
  UpdateClLeadRequest,
} from '../types/clLeadApiTypes';

// CommunityLink leads — wemarketplus-backend/src/communitylink (cl/leads, cl/lead-notes).
//   GET/POST/GET:id/PATCH/DELETE /cl/leads; GET /cl/lead-notes.
export const leadsApi = createApi({
  reducerPath: 'clLeadsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['ClLead', 'ClLeadNote'],
  endpoints: (build) => ({
    listClLeads: build.query<PaginatedPayload<ClLeadRecord>, PaginationParams | void>({
      query: (params) => ({ url: '/cl/leads', params: params ?? undefined }),
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
  }),
});

export const {
  useListClLeadsQuery,
  useGetClLeadQuery,
  useCreateClLeadMutation,
  useUpdateClLeadMutation,
  useDeleteClLeadMutation,
  useListClLeadNotesQuery,
} = leadsApi;
