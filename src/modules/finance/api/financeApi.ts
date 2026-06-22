import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload, PaginationParams } from '@/shared/types';
import type { InvoiceStatus } from '../constants/financeConstants';
import type {
  CreateExpenseReceiptRequest,
  CreateInvoiceRequest,
  CreateMileageLogRequest,
  ExpenseReceiptRecord,
  FinancialSetting,
  InvoiceRecord,
  MileageLogRecord,
  RevenueRecord,
  UpdateRevenueRequest,
} from '../types/financeTypes';

// Grant-CRM finance — wemarketplus-backend revenue, grant-awards, payment-tracking,
// invoices, mileage-logs, expense-receipts, financial-settings. Some resources are
// read + specialised actions (no full CRUD), matching the backend exactly.
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const financeApi = createApi({
  reducerPath: 'financeApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['Invoice', 'Mileage', 'Expense', 'Revenue', 'Payment', 'FinSetting'],
  endpoints: (build) => ({
    // invoices
    listInvoices: build.query<PaginatedPayload<InvoiceRecord>, (PaginationParams & { status?: InvoiceStatus }) | void>({
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
    updateInvoice: build.mutation<InvoiceRecord, { id: string; patch: Partial<CreateInvoiceRequest> }>({
      query: ({ id, patch }) => ({ url: `/invoices/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<InvoiceRecord>,
      invalidatesTags: ['Invoice'],
    }),
    // mileage logs
    listMileageLogs: build.query<PaginatedPayload<MileageLogRecord>, PaginationParams | void>({
      query: (p) => ({ url: '/mileage-logs', params: p ?? undefined }),
      transformResponse: list<MileageLogRecord>,
      providesTags: ['Mileage'],
    }),
    createMileageLog: build.mutation<MileageLogRecord, CreateMileageLogRequest>({
      query: (body) => ({ url: '/mileage-logs', method: 'POST', body }),
      transformResponse: env<MileageLogRecord>,
      invalidatesTags: ['Mileage'],
    }),
    updateMileageLog: build.mutation<MileageLogRecord, { id: string; patch: Partial<CreateMileageLogRequest> }>({
      query: ({ id, patch }) => ({ url: `/mileage-logs/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<MileageLogRecord>,
      invalidatesTags: ['Mileage'],
    }),
    deleteMileageLog: build.mutation<void, string>({
      query: (id) => ({ url: `/mileage-logs/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Mileage'],
    }),
    // expense receipts
    listExpenseReceipts: build.query<PaginatedPayload<ExpenseReceiptRecord>, PaginationParams | void>({
      query: (p) => ({ url: '/expense-receipts', params: p ?? undefined }),
      transformResponse: list<ExpenseReceiptRecord>,
      providesTags: ['Expense'],
    }),
    createExpenseReceipt: build.mutation<ExpenseReceiptRecord, CreateExpenseReceiptRequest>({
      query: (body) => ({ url: '/expense-receipts', method: 'POST', body }),
      transformResponse: env<ExpenseReceiptRecord>,
      invalidatesTags: ['Expense'],
    }),
    reviewExpenseReceipt: build.mutation<ExpenseReceiptRecord, { id: string; approvalStatus: 'approved' | 'rejected' }>({
      query: ({ id, approvalStatus }) => ({ url: `/expense-receipts/${id}/review`, method: 'PATCH', body: { approvalStatus } }),
      transformResponse: env<ExpenseReceiptRecord>,
      invalidatesTags: ['Expense'],
    }),
    deleteExpenseReceipt: build.mutation<void, string>({
      query: (id) => ({ url: `/expense-receipts/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Expense'],
    }),
    // revenue (read + dashboard + PUT)
    getRevenueDashboard: build.query<Record<string, unknown>, void>({
      query: () => ({ url: '/revenue/dashboard' }),
      transformResponse: env<Record<string, unknown>>,
      providesTags: ['Revenue'],
    }),
    listRevenue: build.query<RevenueRecord[], void>({
      query: () => ({ url: '/revenue' }),
      transformResponse: (res: ApiEnvelope<RevenueRecord[] | PaginatedPayload<RevenueRecord>>) =>
        Array.isArray(res.data) ? res.data : res.data.data,
      providesTags: ['Revenue'],
    }),
    updateRevenue: build.mutation<RevenueRecord, { id: string; patch: UpdateRevenueRequest }>({
      query: ({ id, patch }) => ({ url: `/revenue/${id}`, method: 'PUT', body: patch }),
      transformResponse: env<RevenueRecord>,
      invalidatesTags: ['Revenue'],
    }),
    // grant awards (read)
    getGrantAwardsSummary: build.query<Record<string, unknown>, void>({
      query: () => ({ url: '/grant-awards/summary' }),
      transformResponse: env<Record<string, unknown>>,
    }),
    listGrantAwards: build.query<RevenueRecord[], void>({
      query: () => ({ url: '/grant-awards' }),
      transformResponse: (res: ApiEnvelope<RevenueRecord[] | PaginatedPayload<RevenueRecord>>) =>
        Array.isArray(res.data) ? res.data : res.data.data,
      providesTags: ['Revenue'],
    }),
    // payment tracking
    getPaymentSummary: build.query<Record<string, unknown>, void>({
      query: () => ({ url: '/payment-tracking/summary' }),
      transformResponse: env<Record<string, unknown>>,
      providesTags: ['Payment'],
    }),
    listPaymentTracking: build.query<PaginatedPayload<RevenueRecord>, (PaginationParams & { status?: string }) | void>({
      query: (p) => ({ url: '/payment-tracking', params: p ?? undefined }),
      transformResponse: list<RevenueRecord>,
      providesTags: ['Payment'],
    }),
    markPaid: build.mutation<RevenueRecord, { id: string; paymentReceivedDate?: string; paymentMethod?: string; notes?: string }>({
      query: ({ id, ...body }) => ({ url: `/payment-tracking/${id}/mark-paid`, method: 'PUT', body }),
      transformResponse: env<RevenueRecord>,
      invalidatesTags: ['Payment', 'Revenue'],
    }),
    sendInvoice: build.mutation<RevenueRecord, string>({
      query: (id) => ({ url: `/payment-tracking/${id}/send-invoice`, method: 'PUT' }),
      transformResponse: env<RevenueRecord>,
      invalidatesTags: ['Payment', 'Revenue'],
    }),
    // financial settings (key/value)
    getFinancialSettings: build.query<FinancialSetting[], void>({
      query: () => ({ url: '/financial-settings' }),
      transformResponse: (res: ApiEnvelope<FinancialSetting[]>) => res.data,
      providesTags: ['FinSetting'],
    }),
    upsertFinancialSetting: build.mutation<FinancialSetting, FinancialSetting>({
      query: (body) => ({ url: '/financial-settings', method: 'PUT', body }),
      transformResponse: env<FinancialSetting>,
      invalidatesTags: ['FinSetting'],
    }),
  }),
});

export const {
  useListInvoicesQuery,
  useGetInvoiceQuery,
  useCreateInvoiceMutation,
  useUpdateInvoiceMutation,
  useListMileageLogsQuery,
  useCreateMileageLogMutation,
  useUpdateMileageLogMutation,
  useDeleteMileageLogMutation,
  useListExpenseReceiptsQuery,
  useCreateExpenseReceiptMutation,
  useReviewExpenseReceiptMutation,
  useDeleteExpenseReceiptMutation,
  useGetRevenueDashboardQuery,
  useListRevenueQuery,
  useUpdateRevenueMutation,
  useGetGrantAwardsSummaryQuery,
  useListGrantAwardsQuery,
  useGetPaymentSummaryQuery,
  useListPaymentTrackingQuery,
  useMarkPaidMutation,
  useSendInvoiceMutation,
  useGetFinancialSettingsQuery,
  useUpsertFinancialSettingMutation,
} = financeApi;
