import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type {
  CreateFollowUpRequest,
  FollowUpAutomationRecord,
  ListFollowUpsQuery,
} from '../types/automationTypes';

// Verified against wemarketplus-backend/src/automation/automation.controller.ts:
//   GET    /automation/follow-ups?prospectId -> FollowUpAutomationDto[]  (own only)
//   POST   /automation/follow-ups             body:CreateFollowUpDto
//   DELETE /automation/follow-ups/:id         204, cancels (row survives)
//
// The list is a plain array, not PaginatedPayload: the backend returns a bounded
// working list the way the cold-accounts and re-engagement reads do, so there is
// no `total` and nothing to page through.
export const automationApi = createApi({
  reducerPath: 'automationApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['FollowUp'],
  endpoints: (build) => ({
    listFollowUps: build.query<
      FollowUpAutomationRecord[],
      ListFollowUpsQuery | void
    >({
      query: (params) => ({
        url: '/automation/follow-ups',
        params: params ?? undefined,
      }),
      transformResponse: (res: ApiEnvelope<FollowUpAutomationRecord[]>) =>
        res.data,
      providesTags: ['FollowUp'],
    }),
    createFollowUp: build.mutation<
      FollowUpAutomationRecord,
      CreateFollowUpRequest
    >({
      query: (body) => ({
        url: '/automation/follow-ups',
        method: 'POST',
        body,
      }),
      transformResponse: (res: ApiEnvelope<FollowUpAutomationRecord>) =>
        res.data,
      invalidatesTags: ['FollowUp'],
    }),
    // DELETE, but the reminder is cancelled rather than removed — see the
    // controller. Nothing to unwrap: the backend answers 204.
    cancelFollowUp: build.mutation<void, string>({
      query: (id) => ({
        url: `/automation/follow-ups/${id}`,
        method: 'DELETE',
      }),
      invalidatesTags: ['FollowUp'],
    }),
  }),
});

export const {
  useListFollowUpsQuery,
  useCreateFollowUpMutation,
  useCancelFollowUpMutation,
} = automationApi;
