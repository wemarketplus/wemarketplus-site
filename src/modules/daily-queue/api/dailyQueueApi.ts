import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type {
  ClDailyQueue,
  ClFieldQueue,
  DailyQueue,
} from '../types/dailyQueueTypes';

// Verified against the three queue controllers:
//   GET /daily-queue     -> DailyQueueDto    (HospiceLink; always the caller's own,
//                                             no userId param)
//   GET /cl/daily-queue  -> ClDailyQueueDto  (CommunityLink sales; community-wide,
//                                             because cl_leads/cl_tours carry no owner)
//   GET /cl/field-queue  -> ClFieldQueueDto  (CommunityLink field ops; the caller's
//                                             OWN assigned work orders — those tables
//                                             do have assignedTo)
//
// ONE api slice for all three, not three: they are the same screen for different
// audiences, so extra reducerPaths would mean extra caches, middleware entries and
// store registrations for no separation anyone benefits from. The queries are
// skipped by product/role at the call site.
export const dailyQueueApi = createApi({
  reducerPath: 'dailyQueueApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['DailyQueue', 'ClDailyQueue', 'ClFieldQueue'],
  endpoints: (build) => ({
    getDailyQueue: build.query<DailyQueue, void>({
      query: () => ({ url: '/daily-queue' }),
      transformResponse: (res: ApiEnvelope<DailyQueue>) => res.data,
      providesTags: ['DailyQueue'],
    }),
    getClDailyQueue: build.query<ClDailyQueue, void>({
      query: () => ({ url: '/cl/daily-queue' }),
      transformResponse: (res: ApiEnvelope<ClDailyQueue>) => res.data,
      providesTags: ['ClDailyQueue'],
    }),
    getClFieldQueue: build.query<ClFieldQueue, void>({
      query: () => ({ url: '/cl/field-queue' }),
      transformResponse: (res: ApiEnvelope<ClFieldQueue>) => res.data,
      providesTags: ['ClFieldQueue'],
    }),
  }),
});

export const {
  useGetDailyQueueQuery,
  useGetClDailyQueueQuery,
  useGetClFieldQueueQuery,
} = dailyQueueApi;
