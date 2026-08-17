import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload, PaginationParams } from '@/shared/types';
import { cleanListParams } from '@/shared/utils/queryParams';
import type {
  ClApartmentRecord,
  ClCommunityRecord,
  ClHousekeepingTaskRecord,
  ClMaintenanceTicketRecord,
  ClMakeReadyTaskRecord,
  CreateClApartmentRequest,
  CreateClCommunityRequest,
  CreateClHousekeepingTaskRequest,
  CreateClMaintenanceTicketRequest,
  CreateClMakeReadyTaskRequest,
} from '../types/clOperationsApiTypes';

// CommunityLink property operations — wemarketplus-backend/src/communitylink.
// Five uniform-CRUD resources, all under /api:
//   /cl/communities  /cl/apartments  /cl/make-ready-tasks
//   /cl/maintenance-tickets  /cl/housekeeping-tasks
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

// Server-side list params: pagination + search + status filter (ClListQueryDto).
export interface OpsListParams extends PaginationParams {
  search?: string;
  status?: string;
  /**
   * The backend's shared `type` filter (ClListQueryDto). On the make-ready board it
   * maps to `category`, which is what the Make-Ready Clean view narrows on —
   * server-side, because the list is paginated and filtering the fetched page would
   * show a cleaner part of their pipeline and call it all of it.
   */
  type?: string;
}

export const clOperationsApi = createApi({
  reducerPath: 'clOperationsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['ClCommunity', 'ClApartment', 'ClMakeReady', 'ClMaintenance', 'ClHousekeeping'],
  endpoints: (build) => ({
    // communities
    listClCommunities: build.query<PaginatedPayload<ClCommunityRecord>, PaginationParams | void>({
      query: (p) => ({ url: '/cl/communities', params: p ?? undefined }),
      transformResponse: list<ClCommunityRecord>,
      providesTags: ['ClCommunity'],
    }),
    createClCommunity: build.mutation<ClCommunityRecord, CreateClCommunityRequest>({
      query: (body) => ({ url: '/cl/communities', method: 'POST', body }),
      transformResponse: env<ClCommunityRecord>,
      invalidatesTags: ['ClCommunity'],
    }),
    updateClCommunity: build.mutation<ClCommunityRecord, { id: string; patch: Partial<CreateClCommunityRequest> }>({
      query: ({ id, patch }) => ({ url: `/cl/communities/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<ClCommunityRecord>,
      invalidatesTags: ['ClCommunity'],
    }),
    deleteClCommunity: build.mutation<void, string>({
      query: (id) => ({ url: `/cl/communities/${id}`, method: 'DELETE' }),
      invalidatesTags: ['ClCommunity'],
    }),
    // apartments
    listClApartments: build.query<PaginatedPayload<ClApartmentRecord>, OpsListParams | void>({
      query: (p) => ({ url: '/cl/apartments', params: cleanListParams(p ?? undefined) }),
      transformResponse: list<ClApartmentRecord>,
      providesTags: ['ClApartment'],
    }),
    createClApartment: build.mutation<ClApartmentRecord, CreateClApartmentRequest>({
      query: (body) => ({ url: '/cl/apartments', method: 'POST', body }),
      transformResponse: env<ClApartmentRecord>,
      invalidatesTags: ['ClApartment'],
    }),
    updateClApartment: build.mutation<ClApartmentRecord, { id: string; patch: Partial<CreateClApartmentRequest> }>({
      query: ({ id, patch }) => ({ url: `/cl/apartments/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<ClApartmentRecord>,
      invalidatesTags: ['ClApartment'],
    }),
    deleteClApartment: build.mutation<void, string>({
      query: (id) => ({ url: `/cl/apartments/${id}`, method: 'DELETE' }),
      invalidatesTags: ['ClApartment'],
    }),
    // make-ready tasks
    listClMakeReady: build.query<PaginatedPayload<ClMakeReadyTaskRecord>, OpsListParams | void>({
      query: (p) => ({ url: '/cl/make-ready-tasks', params: cleanListParams(p ?? undefined) }),
      transformResponse: list<ClMakeReadyTaskRecord>,
      providesTags: ['ClMakeReady'],
    }),
    createClMakeReady: build.mutation<ClMakeReadyTaskRecord, CreateClMakeReadyTaskRequest>({
      query: (body) => ({ url: '/cl/make-ready-tasks', method: 'POST', body }),
      transformResponse: env<ClMakeReadyTaskRecord>,
      invalidatesTags: ['ClMakeReady'],
    }),
    updateClMakeReady: build.mutation<ClMakeReadyTaskRecord, { id: string; patch: Partial<CreateClMakeReadyTaskRequest> }>({
      query: ({ id, patch }) => ({ url: `/cl/make-ready-tasks/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<ClMakeReadyTaskRecord>,
      invalidatesTags: ['ClMakeReady'],
    }),
    deleteClMakeReady: build.mutation<void, string>({
      query: (id) => ({ url: `/cl/make-ready-tasks/${id}`, method: 'DELETE' }),
      invalidatesTags: ['ClMakeReady'],
    }),
    // maintenance tickets
    listClMaintenance: build.query<PaginatedPayload<ClMaintenanceTicketRecord>, OpsListParams | void>({
      query: (p) => ({ url: '/cl/maintenance-tickets', params: cleanListParams(p ?? undefined) }),
      transformResponse: list<ClMaintenanceTicketRecord>,
      providesTags: ['ClMaintenance'],
    }),
    createClMaintenance: build.mutation<ClMaintenanceTicketRecord, CreateClMaintenanceTicketRequest>({
      query: (body) => ({ url: '/cl/maintenance-tickets', method: 'POST', body }),
      transformResponse: env<ClMaintenanceTicketRecord>,
      invalidatesTags: ['ClMaintenance'],
    }),
    updateClMaintenance: build.mutation<ClMaintenanceTicketRecord, { id: string; patch: Partial<CreateClMaintenanceTicketRequest> }>({
      query: ({ id, patch }) => ({ url: `/cl/maintenance-tickets/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<ClMaintenanceTicketRecord>,
      invalidatesTags: ['ClMaintenance'],
    }),
    deleteClMaintenance: build.mutation<void, string>({
      query: (id) => ({ url: `/cl/maintenance-tickets/${id}`, method: 'DELETE' }),
      invalidatesTags: ['ClMaintenance'],
    }),
    // housekeeping tasks
    listClHousekeeping: build.query<PaginatedPayload<ClHousekeepingTaskRecord>, OpsListParams | void>({
      query: (p) => ({ url: '/cl/housekeeping-tasks', params: cleanListParams(p ?? undefined) }),
      transformResponse: list<ClHousekeepingTaskRecord>,
      providesTags: ['ClHousekeeping'],
    }),
    createClHousekeeping: build.mutation<ClHousekeepingTaskRecord, CreateClHousekeepingTaskRequest>({
      query: (body) => ({ url: '/cl/housekeeping-tasks', method: 'POST', body }),
      transformResponse: env<ClHousekeepingTaskRecord>,
      invalidatesTags: ['ClHousekeeping'],
    }),
    updateClHousekeeping: build.mutation<ClHousekeepingTaskRecord, { id: string; patch: Partial<CreateClHousekeepingTaskRequest> }>({
      query: ({ id, patch }) => ({ url: `/cl/housekeeping-tasks/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<ClHousekeepingTaskRecord>,
      invalidatesTags: ['ClHousekeeping'],
    }),
    deleteClHousekeeping: build.mutation<void, string>({
      query: (id) => ({ url: `/cl/housekeeping-tasks/${id}`, method: 'DELETE' }),
      invalidatesTags: ['ClHousekeeping'],
    }),
  }),
});

export const {
  useListClCommunitiesQuery,
  useCreateClCommunityMutation,
  useUpdateClCommunityMutation,
  useDeleteClCommunityMutation,
  useListClApartmentsQuery,
  useCreateClApartmentMutation,
  useUpdateClApartmentMutation,
  useDeleteClApartmentMutation,
  useListClMakeReadyQuery,
  useCreateClMakeReadyMutation,
  useUpdateClMakeReadyMutation,
  useDeleteClMakeReadyMutation,
  useListClMaintenanceQuery,
  useCreateClMaintenanceMutation,
  useUpdateClMaintenanceMutation,
  useDeleteClMaintenanceMutation,
  useListClHousekeepingQuery,
  useCreateClHousekeepingMutation,
  useUpdateClHousekeepingMutation,
  useDeleteClHousekeepingMutation,
} = clOperationsApi;
