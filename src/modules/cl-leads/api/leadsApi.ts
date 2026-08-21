import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
// Deep import, not the module barrel: `@/modules/daily-queue` also exports its
// PAGES, and ClDailyTasksPage imports cl-leads' own constants — so going through
// the barrel would close an import cycle (leadsApi -> daily-queue -> cl-leads ->
// leadsApi) for the sake of one api slice. Same reason useAppointmentActions
// reaches for '@/modules/jobs/api/jobsApi' directly.
import { dailyQueueApi } from '@/modules/daily-queue/api/dailyQueueApi';
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

/**
 * Refreshes the caches OUTSIDE this slice that are built from leads.
 *
 * RTK Query tag invalidation is per-api: `invalidatesTags: ['ClLead']` refetches
 * every lead query in THIS slice and nothing else. The CommunityLink daily queue
 * is a different slice (dailyQueueApi, reducerPath `dailyQueueApi`) over
 * /cl/daily-queue, and the server builds that response out of cl_leads — follow-ups
 * whose date has arrived, and active leads that have gone quiet. So creating a lead
 * left the queue showing its previous answer until the page was reloaded: 6 items
 * before, 7 after F5, with the new lead missing from the list in between.
 *
 * Invalidating by TAG rather than pushing the new row in: the queue's buckets and
 * ordering are decided server-side, so the only correct next state is the one the
 * server computes.
 *
 * `ClFieldQueue` is deliberately NOT invalidated — it is work orders, which no lead
 * mutation can change. Same pattern as useAppointmentActions invalidating jobsApi
 * after a completed visit chains a follow-up job.
 */
const invalidateLeadDerivedCaches = async (
  queryFulfilled: Promise<unknown>,
  dispatch: (action: unknown) => unknown,
): Promise<void> => {
  try {
    await queryFulfilled;
  } catch {
    // A failed write changes nothing, so there is nothing to refetch. Swallowed
    // rather than rethrown: the caller's own `.unwrap()` already surfaces it.
    return;
  }
  dispatch(dailyQueueApi.util.invalidateTags(['ClDailyQueue']));
};

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
      onQueryStarted: (_arg, { dispatch, queryFulfilled }) =>
        invalidateLeadDerivedCaches(queryFulfilled, dispatch),
    }),
    updateClLead: build.mutation<ClLeadRecord, { id: string; patch: UpdateClLeadRequest }>({
      query: ({ id, patch }) => ({ url: `/cl/leads/${id}`, method: 'PATCH', body: patch }),
      transformResponse: (res: ApiEnvelope<ClLeadRecord>) => res.data,
      invalidatesTags: ['ClLead'],
      // Stage and follow-up date are exactly what the queue buckets by, so an
      // edit moves a lead between its sections as often as a create adds one.
      onQueryStarted: (_arg, { dispatch, queryFulfilled }) =>
        invalidateLeadDerivedCaches(queryFulfilled, dispatch),
    }),
    deleteClLead: build.mutation<void, string>({
      query: (id) => ({ url: `/cl/leads/${id}`, method: 'DELETE' }),
      invalidatesTags: ['ClLead'],
      onQueryStarted: (_arg, { dispatch, queryFulfilled }) =>
        invalidateLeadDerivedCaches(queryFulfilled, dispatch),
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
