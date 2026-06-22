import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload } from '@/shared/types';
import type {
  ContactRecord,
  CreateContactRequest,
  ListContactsQuery,
  UpdateContactRequest,
} from '../types/contactsTypes';

// Grant-CRM contacts (polymorphic — attach to any record) — src/contacts.
//   GET/POST/GET:id/PATCH/DELETE  /contacts?recordType&recordId
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const contactsApi = createApi({
  reducerPath: 'contactsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['Contact'],
  endpoints: (build) => ({
    listContacts: build.query<PaginatedPayload<ContactRecord>, ListContactsQuery | void>({
      query: (p) => ({ url: '/contacts', params: p ?? undefined }),
      transformResponse: list<ContactRecord>,
      providesTags: ['Contact'],
    }),
    getContact: build.query<ContactRecord, string>({
      query: (id) => ({ url: `/contacts/${id}` }),
      transformResponse: env<ContactRecord>,
      providesTags: ['Contact'],
    }),
    createContact: build.mutation<ContactRecord, CreateContactRequest>({
      query: (body) => ({ url: '/contacts', method: 'POST', body }),
      transformResponse: env<ContactRecord>,
      invalidatesTags: ['Contact'],
    }),
    updateContact: build.mutation<ContactRecord, { id: string; patch: UpdateContactRequest }>({
      query: ({ id, patch }) => ({ url: `/contacts/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<ContactRecord>,
      invalidatesTags: ['Contact'],
    }),
    deleteContact: build.mutation<void, string>({
      query: (id) => ({ url: `/contacts/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Contact'],
    }),
  }),
});

export const {
  useListContactsQuery,
  useGetContactQuery,
  useCreateContactMutation,
  useUpdateContactMutation,
  useDeleteContactMutation,
} = contactsApi;
