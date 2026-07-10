import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload, PaginationParams } from '@/shared/types';
import type {
  CreateWibRequest,
  ListWibsQuery,
  UpdateWibRequest,
  WibRecord,
  WibViewPref,
} from '../types/wibsTypes';

// Grant-CRM Workforce Investment Boards — wemarketplus-backend/src/wibs.
//   GET /wibs (+ /wibs/my), GET /wibs/:id, POST /wibs, PATCH /wibs/:id,
//   PUT /wibs/:id/territory, DELETE /wibs/:id, GET/PUT /me/wib-view.
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const wibsApi = createApi({
  reducerPath: 'wibsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['Wib', 'WibView'],
  endpoints: (build) => ({
    listWibs: build.query<PaginatedPayload<WibRecord>, ListWibsQuery | void>({
      query: (p) => ({ url: '/wibs', params: p ?? undefined }),
      transformResponse: list<WibRecord>,
      providesTags: ['Wib'],
    }),
    listMyWibs: build.query<PaginatedPayload<WibRecord>, PaginationParams | void>({
      query: (p) => ({ url: '/wibs/my', params: p ?? undefined }),
      transformResponse: list<WibRecord>,
      providesTags: ['Wib'],
    }),
    getWib: build.query<WibRecord, string>({
      query: (id) => ({ url: `/wibs/${id}` }),
      transformResponse: env<WibRecord>,
      providesTags: ['Wib'],
    }),
    createWib: build.mutation<WibRecord, CreateWibRequest>({
      query: (body) => ({ url: '/wibs', method: 'POST', body }),
      transformResponse: env<WibRecord>,
      invalidatesTags: ['Wib'],
    }),
    updateWib: build.mutation<WibRecord, { id: string; patch: UpdateWibRequest }>({
      query: ({ id, patch }) => ({ url: `/wibs/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<WibRecord>,
      invalidatesTags: ['Wib'],
    }),
    deleteWib: build.mutation<void, string>({
      query: (id) => ({ url: `/wibs/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Wib'],
    }),
    setWibTerritory: build.mutation<WibRecord, { id: string; territoryId: string | null }>({
      query: ({ id, territoryId }) => ({ url: `/wibs/${id}/territory`, method: 'PUT', body: { territoryId } }),
      transformResponse: env<WibRecord>,
      invalidatesTags: ['Wib'],
    }),
    getWibView: build.query<WibViewPref, void>({
      query: () => ({ url: '/me/wib-view' }),
      transformResponse: env<WibViewPref>,
      providesTags: ['WibView'],
    }),
    setWibView: build.mutation<WibViewPref, WibViewPref>({
      query: (body) => ({ url: '/me/wib-view', method: 'PUT', body }),
      transformResponse: env<WibViewPref>,
      invalidatesTags: ['WibView'],
    }),
  }),
});

export const {
  useListWibsQuery,
  useListMyWibsQuery,
  useGetWibQuery,
  useCreateWibMutation,
  useUpdateWibMutation,
  useDeleteWibMutation,
  useSetWibTerritoryMutation,
  useGetWibViewQuery,
  useSetWibViewMutation,
} = wibsApi;
