import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload } from '@/shared/types';
import type {
  ActivityFeedItem,
  CreateGoalRequest,
  CreateNoteRequest,
  CreateTaskRequest,
  GoalRecord,
  ListNotesQuery,
  ListTasksQuery,
  NoteRecord,
  TaskRecord,
  UpdateGoalRequest,
  UpdateNoteRequest,
  UpdateTaskRequest,
} from '../types/activityTypes';

// The activity page aggregates three backend resources, all under /api. Full
// CRUD matching the backend controllers:
//   tasks: GET list, POST, GET/:id, PATCH/:id, DELETE/:id
//   notes: GET list, POST, GET/:id, PATCH/:id            (no DELETE on backend)
//   goals: GET list, POST, GET/:id, PATCH/:id, DELETE/:id
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const activityApi = createApi({
  reducerPath: 'activityApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['Task', 'Note', 'Goal', 'Activity'],
  endpoints: (build) => ({
    // activity feed (GET /activity?resource&resourceId&limit) — audit-style feed
    // available to any authenticated user, excludes NOTE/TASK actions.
    listActivityFeed: build.query<ActivityFeedItem[], { resource?: string; resourceId?: string; limit?: number } | void>({
      query: (params) => ({ url: '/activity', params: params ?? undefined }),
      transformResponse: (res: ApiEnvelope<{ data: ActivityFeedItem[] }>) => res.data.data,
      providesTags: ['Activity'],
    }),
    // tasks
    listTasks: build.query<PaginatedPayload<TaskRecord>, ListTasksQuery | void>({
      query: (params) => ({ url: '/tasks', params: params ?? undefined }),
      transformResponse: list<TaskRecord>,
      providesTags: ['Task'],
    }),
    getTask: build.query<TaskRecord, string>({
      query: (id) => ({ url: `/tasks/${id}` }),
      transformResponse: env<TaskRecord>,
      providesTags: ['Task'],
    }),
    createTask: build.mutation<TaskRecord, CreateTaskRequest>({
      query: (body) => ({ url: '/tasks', method: 'POST', body }),
      transformResponse: env<TaskRecord>,
      invalidatesTags: ['Task'],
    }),
    updateTask: build.mutation<TaskRecord, { id: string; patch: UpdateTaskRequest }>({
      query: ({ id, patch }) => ({ url: `/tasks/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<TaskRecord>,
      invalidatesTags: ['Task'],
    }),
    deleteTask: build.mutation<void, string>({
      query: (id) => ({ url: `/tasks/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Task'],
    }),
    // notes
    listNotes: build.query<PaginatedPayload<NoteRecord>, ListNotesQuery | void>({
      query: (params) => ({ url: '/notes', params: params ?? undefined }),
      transformResponse: list<NoteRecord>,
      providesTags: ['Note'],
    }),
    getNote: build.query<NoteRecord, string>({
      query: (id) => ({ url: `/notes/${id}` }),
      transformResponse: env<NoteRecord>,
      providesTags: ['Note'],
    }),
    createNote: build.mutation<NoteRecord, CreateNoteRequest>({
      query: (body) => ({ url: '/notes', method: 'POST', body }),
      transformResponse: env<NoteRecord>,
      invalidatesTags: ['Note'],
    }),
    updateNote: build.mutation<NoteRecord, { id: string; patch: UpdateNoteRequest }>({
      query: ({ id, patch }) => ({ url: `/notes/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<NoteRecord>,
      invalidatesTags: ['Note'],
    }),
    // goals
    listGoals: build.query<PaginatedPayload<GoalRecord>, { userId?: string } | void>({
      query: (params) => ({ url: '/goals', params: params ?? undefined }),
      transformResponse: list<GoalRecord>,
      providesTags: ['Goal'],
    }),
    getGoal: build.query<GoalRecord, string>({
      query: (id) => ({ url: `/goals/${id}` }),
      transformResponse: env<GoalRecord>,
      providesTags: ['Goal'],
    }),
    createGoal: build.mutation<GoalRecord, CreateGoalRequest>({
      query: (body) => ({ url: '/goals', method: 'POST', body }),
      transformResponse: env<GoalRecord>,
      invalidatesTags: ['Goal'],
    }),
    updateGoal: build.mutation<GoalRecord, { id: string; patch: UpdateGoalRequest }>({
      query: ({ id, patch }) => ({ url: `/goals/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<GoalRecord>,
      invalidatesTags: ['Goal'],
    }),
    deleteGoal: build.mutation<void, string>({
      query: (id) => ({ url: `/goals/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Goal'],
    }),
  }),
});

export const {
  useListActivityFeedQuery,
  useListTasksQuery,
  useGetTaskQuery,
  useCreateTaskMutation,
  useUpdateTaskMutation,
  useDeleteTaskMutation,
  useListNotesQuery,
  useGetNoteQuery,
  useCreateNoteMutation,
  useUpdateNoteMutation,
  useListGoalsQuery,
  useGetGoalQuery,
  useCreateGoalMutation,
  useUpdateGoalMutation,
  useDeleteGoalMutation,
} = activityApi;
