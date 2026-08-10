import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type { DailyQueue } from '../types/dailyQueueTypes';

// Verified against wemarketplus-backend/src/daily-queue/daily-queue.controller.ts:
//   GET /daily-queue -> DailyQueueDto   (always the caller's own; no userId param)
export const dailyQueueApi = createApi({
  reducerPath: 'dailyQueueApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['DailyQueue'],
  endpoints: (build) => ({
    getDailyQueue: build.query<DailyQueue, void>({
      query: () => ({ url: '/daily-queue' }),
      transformResponse: (res: ApiEnvelope<DailyQueue>) => res.data,
      providesTags: ['DailyQueue'],
    }),
  }),
});

export const { useGetDailyQueueQuery } = dailyQueueApi;
