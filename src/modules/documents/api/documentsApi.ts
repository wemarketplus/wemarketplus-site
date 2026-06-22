import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload } from '@/shared/types';
import type { CreateDocumentRequest, DocumentRecord } from '../types/documentsTypes';

// Grant-CRM documents — wemarketplus-backend/src/documents.
//   employer-documents: GET/POST require ?companyId=; DELETE /:id (admin/owner)
//   wib-documents:      GET/POST require ?wibId=;     DELETE /:id (admin/owner)
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const documentsApi = createApi({
  reducerPath: 'documentsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['EmployerDoc', 'WibDoc'],
  endpoints: (build) => ({
    listEmployerDocuments: build.query<PaginatedPayload<DocumentRecord>, { companyId: string; page?: number; limit?: number; documentType?: string }>({
      query: (params) => ({ url: '/employer-documents', params }),
      transformResponse: list<DocumentRecord>,
      providesTags: ['EmployerDoc'],
    }),
    createEmployerDocument: build.mutation<DocumentRecord, { companyId: string; body: CreateDocumentRequest }>({
      query: ({ companyId, body }) => ({ url: '/employer-documents', method: 'POST', params: { companyId }, body }),
      transformResponse: env<DocumentRecord>,
      invalidatesTags: ['EmployerDoc'],
    }),
    deleteEmployerDocument: build.mutation<void, string>({
      query: (id) => ({ url: `/employer-documents/${id}`, method: 'DELETE' }),
      invalidatesTags: ['EmployerDoc'],
    }),
    listWibDocuments: build.query<PaginatedPayload<DocumentRecord>, { wibId: string; page?: number; limit?: number; documentType?: string }>({
      query: (params) => ({ url: '/wib-documents', params }),
      transformResponse: list<DocumentRecord>,
      providesTags: ['WibDoc'],
    }),
    createWibDocument: build.mutation<DocumentRecord, { wibId: string; body: CreateDocumentRequest }>({
      query: ({ wibId, body }) => ({ url: '/wib-documents', method: 'POST', params: { wibId }, body }),
      transformResponse: env<DocumentRecord>,
      invalidatesTags: ['WibDoc'],
    }),
    deleteWibDocument: build.mutation<void, string>({
      query: (id) => ({ url: `/wib-documents/${id}`, method: 'DELETE' }),
      invalidatesTags: ['WibDoc'],
    }),
  }),
});

export const {
  useListEmployerDocumentsQuery,
  useCreateEmployerDocumentMutation,
  useDeleteEmployerDocumentMutation,
  useListWibDocumentsQuery,
  useCreateWibDocumentMutation,
  useDeleteWibDocumentMutation,
} = documentsApi;
