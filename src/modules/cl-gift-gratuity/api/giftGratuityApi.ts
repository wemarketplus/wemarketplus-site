import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload, PaginationParams } from '@/shared/types';
import type {
  CreateGiftGratuityLogRequest,
  GiftGratuityLogRecord,
} from '../types/giftGratuityApiTypes';

// wemarketplus-backend/src/gift-gratuity — GET/POST /gift-gratuity-logs.
// Append-only: no update/delete endpoints exist (immutable compliance trail).
export const giftGratuityApi = createApi({
  reducerPath: 'giftGratuityApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['GiftGratuityLog'],
  endpoints: (build) => ({
    listGiftGratuityLogs: build.query<PaginatedPayload<GiftGratuityLogRecord>, PaginationParams | void>({
      query: (params) => ({ url: '/gift-gratuity-logs', params: params ?? undefined }),
      transformResponse: (res: ApiEnvelope<PaginatedPayload<GiftGratuityLogRecord>>) => res.data,
      providesTags: ['GiftGratuityLog'],
    }),
    createGiftGratuityLog: build.mutation<GiftGratuityLogRecord, CreateGiftGratuityLogRequest>({
      query: (body) => ({ url: '/gift-gratuity-logs', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<GiftGratuityLogRecord>) => res.data,
      invalidatesTags: ['GiftGratuityLog'],
    }),
  }),
});

export const { useListGiftGratuityLogsQuery, useCreateGiftGratuityLogMutation } = giftGratuityApi;
