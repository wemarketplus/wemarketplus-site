import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload, Prospect } from '@/shared/types';
import { PROSPECTS_TAGS } from '../constants/prospectsConstants';

// TODO(backend): ship /prospects CRUD endpoints with the shape below.
//   GET    /prospects?page=&limit=&status=&urgency=&q=
//   GET    /prospects/:id
//   POST   /prospects
//   PATCH  /prospects/:id
//   DELETE /prospects/:id
//
// Until then `useProspectsList` falls back to PROSPECTS_FIXTURE — the slice
// declaration here keeps types real so the UI doesn't drift.
export const prospectsApi = createApi({
  reducerPath: 'prospectsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: [PROSPECTS_TAGS.List, PROSPECTS_TAGS.Detail],
  endpoints: (build) => ({
    listProspects: build.query<PaginatedPayload<Prospect>, { page?: number; limit?: number }>({
      query: (params = {}) => ({ url: '/prospects', params }),
      transformResponse: (res: ApiEnvelope<PaginatedPayload<Prospect>>) => res.data,
      providesTags: [{ type: PROSPECTS_TAGS.List, id: 'PARTIAL-LIST' }],
    }),
  }),
});

export const { useListProspectsQuery } = prospectsApi;
