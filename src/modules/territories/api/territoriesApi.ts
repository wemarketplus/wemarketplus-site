import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload, PaginationParams } from '@/shared/types';
import type {
  CreateTerritoryRequest,
  TerritoryRecord,
  UpdateTerritoryRequest,
} from '../types/territoriesTypes';

// Grant-CRM territories — wemarketplus-backend/src/territories.
//   GET/POST/GET:id/PATCH/DELETE /territories.
//   Per-user assignment: GET/PUT /users/:userId/territories.
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const territoriesApi = createApi({
  reducerPath: 'territoriesApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['Territory', 'UserTerritory'],
  endpoints: (build) => ({
    listTerritories: build.query<PaginatedPayload<TerritoryRecord>, PaginationParams | void>({
      query: (p) => ({ url: '/territories', params: p ?? undefined }),
      transformResponse: list<TerritoryRecord>,
      providesTags: ['Territory'],
    }),
    getTerritory: build.query<TerritoryRecord, string>({
      query: (id) => ({ url: `/territories/${id}` }),
      transformResponse: env<TerritoryRecord>,
      providesTags: ['Territory'],
    }),
    createTerritory: build.mutation<TerritoryRecord, CreateTerritoryRequest>({
      query: (body) => ({ url: '/territories', method: 'POST', body }),
      transformResponse: env<TerritoryRecord>,
      invalidatesTags: ['Territory'],
    }),
    updateTerritory: build.mutation<TerritoryRecord, { id: string; patch: UpdateTerritoryRequest }>({
      query: ({ id, patch }) => ({ url: `/territories/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<TerritoryRecord>,
      invalidatesTags: ['Territory'],
    }),
    deleteTerritory: build.mutation<void, string>({
      query: (id) => ({ url: `/territories/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Territory'],
    }),
    // Per-user territory assignment (users/:userId/territories).
    listUserTerritories: build.query<TerritoryRecord[], string>({
      query: (userId) => ({ url: `/users/${userId}/territories` }),
      transformResponse: env<TerritoryRecord[]>,
      providesTags: ['UserTerritory'],
    }),
    assignUserTerritories: build.mutation<TerritoryRecord[], { userId: string; territoryIds: string[] }>({
      query: ({ userId, territoryIds }) => ({
        url: `/users/${userId}/territories`,
        method: 'PUT',
        body: { territoryIds },
      }),
      transformResponse: env<TerritoryRecord[]>,
      invalidatesTags: ['UserTerritory'],
    }),
  }),
});

export const {
  useListTerritoriesQuery,
  useGetTerritoryQuery,
  useCreateTerritoryMutation,
  useUpdateTerritoryMutation,
  useDeleteTerritoryMutation,
  useListUserTerritoriesQuery,
  useAssignUserTerritoriesMutation,
} = territoriesApi;
