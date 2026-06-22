import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload, PaginationParams } from '@/shared/types';
import type {
  CreateRosterRequest,
  CreateTrainingProviderRequest,
  ListRostersQuery,
  RosterRecord,
  TrainingProviderRecord,
} from '../types/trainingTypes';

// Grant-CRM training — wemarketplus-backend/src/training-providers, training-rosters.
//   /training-providers  (+ /stats; CSV/XLSX exports via utils/trainingExportUrls)
//   /training-rosters    (+ /import; export via utils/trainingExportUrls)
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const trainingApi = createApi({
  reducerPath: 'trainingApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['TrainingProvider', 'Roster'],
  endpoints: (build) => ({
    listTrainingProviders: build.query<PaginatedPayload<TrainingProviderRecord>, (PaginationParams & { search?: string }) | void>({
      query: (p) => ({ url: '/training-providers', params: p ?? undefined }),
      transformResponse: list<TrainingProviderRecord>,
      providesTags: ['TrainingProvider'],
    }),
    getTrainingProvider: build.query<TrainingProviderRecord, string>({
      query: (id) => ({ url: `/training-providers/${id}` }),
      transformResponse: env<TrainingProviderRecord>,
      providesTags: ['TrainingProvider'],
    }),
    getTrainingProviderStats: build.query<Record<string, number>, void>({
      query: () => ({ url: '/training-providers/stats' }),
      transformResponse: env<Record<string, number>>,
    }),
    createTrainingProvider: build.mutation<TrainingProviderRecord, CreateTrainingProviderRequest>({
      query: (body) => ({ url: '/training-providers', method: 'POST', body }),
      transformResponse: env<TrainingProviderRecord>,
      invalidatesTags: ['TrainingProvider'],
    }),
    updateTrainingProvider: build.mutation<TrainingProviderRecord, { id: string; patch: Partial<CreateTrainingProviderRequest> }>({
      query: ({ id, patch }) => ({ url: `/training-providers/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<TrainingProviderRecord>,
      invalidatesTags: ['TrainingProvider'],
    }),
    deleteTrainingProvider: build.mutation<void, string>({
      query: (id) => ({ url: `/training-providers/${id}`, method: 'DELETE' }),
      invalidatesTags: ['TrainingProvider'],
    }),
    // rosters
    listRosters: build.query<PaginatedPayload<RosterRecord>, ListRostersQuery | void>({
      query: (p) => ({ url: '/training-rosters', params: p ?? undefined }),
      transformResponse: list<RosterRecord>,
      providesTags: ['Roster'],
    }),
    getRoster: build.query<RosterRecord, string>({
      query: (id) => ({ url: `/training-rosters/${id}` }),
      transformResponse: env<RosterRecord>,
      providesTags: ['Roster'],
    }),
    createRoster: build.mutation<RosterRecord, CreateRosterRequest>({
      query: (body) => ({ url: '/training-rosters', method: 'POST', body }),
      transformResponse: env<RosterRecord>,
      invalidatesTags: ['Roster'],
    }),
    importRosters: build.mutation<{ imported: number } | Record<string, unknown>, { applicationId: string; rows: Record<string, unknown>[] }>({
      query: (body) => ({ url: '/training-rosters/import', method: 'POST', body }),
      transformResponse: env<{ imported: number } | Record<string, unknown>>,
      invalidatesTags: ['Roster'],
    }),
    updateRoster: build.mutation<RosterRecord, { id: string; patch: Partial<CreateRosterRequest> }>({
      query: ({ id, patch }) => ({ url: `/training-rosters/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<RosterRecord>,
      invalidatesTags: ['Roster'],
    }),
    deleteRoster: build.mutation<void, string>({
      query: (id) => ({ url: `/training-rosters/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Roster'],
    }),
  }),
});

export const {
  useListTrainingProvidersQuery,
  useGetTrainingProviderQuery,
  useGetTrainingProviderStatsQuery,
  useCreateTrainingProviderMutation,
  useUpdateTrainingProviderMutation,
  useDeleteTrainingProviderMutation,
  useListRostersQuery,
  useGetRosterQuery,
  useCreateRosterMutation,
  useImportRostersMutation,
  useUpdateRosterMutation,
  useDeleteRosterMutation,
} = trainingApi;
