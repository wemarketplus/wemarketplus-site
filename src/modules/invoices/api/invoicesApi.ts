import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload } from '@/shared/types';
import type {
  CreateInvoiceRequest,
  InvoiceRecord,
  ListInvoicesQuery,
  UpdateInvoiceRequest,
} from '../types/invoicesTypes';

// Grant-CRM invoices — src/invoices. Standard REST minus DELETE (the backend
// exposes no delete). POST/PATCH require the `manage_invoices` permission; a
// non-permitted user gets a 403 surfaced by the mutation's error toast.
//   GET/POST  /invoices          GET/PATCH  /invoices/:id
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const invoicesApi = createApi({
  reducerPath: 'invoicesApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['Invoice'],
  endpoints: (build) => ({
    listInvoices: build.query<PaginatedPayload<InvoiceRecord>, ListInvoicesQuery | void>({
      query: (p) => ({ url: '/invoices', params: p ?? undefined }),
      transformResponse: list<InvoiceRecord>,
      providesTags: ['Invoice'],
    }),
    getInvoice: build.query<InvoiceRecord, string>({
      query: (id) => ({ url: `/invoices/${id}` }),
      transformResponse: env<InvoiceRecord>,
      providesTags: ['Invoice'],
    }),
    createInvoice: build.mutation<InvoiceRecord, CreateInvoiceRequest>({
      query: (body) => ({ url: '/invoices', method: 'POST', body }),
      transformResponse: env<InvoiceRecord>,
      invalidatesTags: ['Invoice'],
    }),
    updateInvoice: build.mutation<InvoiceRecord, { id: string; patch: UpdateInvoiceRequest }>({
      query: ({ id, patch }) => ({ url: `/invoices/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<InvoiceRecord>,
      invalidatesTags: ['Invoice'],
    }),
  }),
});

export const {
  useListInvoicesQuery,
  useGetInvoiceQuery,
  useCreateInvoiceMutation,
  useUpdateInvoiceMutation,
} = invoicesApi;
