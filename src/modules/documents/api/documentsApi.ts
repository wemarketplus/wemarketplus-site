import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload } from '@/shared/types';
import type { CreateDocumentRequest, DocumentRecord } from '../types/documentsTypes';

// Grant-CRM documents — wemarketplus-backend/src/documents.
//   employer-documents: GET/POST require ?companyId=; DELETE /:id (admin/owner)
// The backend also exposes /wib-documents (Grants-domain Workforce Investment
// Boards). Deliberately NOT wired here: WIB has no meaning in this CRM and is not
// surfaced anywhere in the UI.
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const documentsApi = createApi({
  reducerPath: 'documentsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['EmployerDoc'],
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
  }),
});

export const {
  useListEmployerDocumentsQuery,
  useCreateEmployerDocumentMutation,
  useDeleteEmployerDocumentMutation,
} = documentsApi;
