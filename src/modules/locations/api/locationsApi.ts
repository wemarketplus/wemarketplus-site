import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload } from '@/shared/types';
import type {
  CreateLocationRequest,
  ListLocationsQuery,
  LocationRecord,
  UpdateLocationRequest,
} from '../types/locationsTypes';

// Grant-CRM employer locations — wemarketplus-backend/src/locations.
//   GET/POST/GET:id/PATCH/DELETE  /locations?state&status&wibId&search
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const locationsApi = createApi({
  reducerPath: 'locationsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['Location'],
  endpoints: (build) => ({
    listLocations: build.query<PaginatedPayload<LocationRecord>, ListLocationsQuery | void>({
      query: (p) => ({ url: '/locations', params: p ?? undefined }),
      transformResponse: list<LocationRecord>,
      providesTags: ['Location'],
    }),
    getLocation: build.query<LocationRecord, string>({
      query: (id) => ({ url: `/locations/${id}` }),
      transformResponse: env<LocationRecord>,
      providesTags: ['Location'],
    }),
    createLocation: build.mutation<LocationRecord, CreateLocationRequest>({
      query: (body) => ({ url: '/locations', method: 'POST', body }),
      transformResponse: env<LocationRecord>,
      invalidatesTags: ['Location'],
    }),
    updateLocation: build.mutation<LocationRecord, { id: string; patch: UpdateLocationRequest }>({
      query: ({ id, patch }) => ({ url: `/locations/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<LocationRecord>,
      invalidatesTags: ['Location'],
    }),
    deleteLocation: build.mutation<void, string>({
      query: (id) => ({ url: `/locations/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Location'],
    }),
  }),
});

export const {
  useListLocationsQuery,
  useGetLocationQuery,
  useCreateLocationMutation,
  useUpdateLocationMutation,
  useDeleteLocationMutation,
} = locationsApi;
