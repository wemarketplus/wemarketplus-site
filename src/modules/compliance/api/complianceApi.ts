import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type {
  AuditLogItem,
  BaaRecord,
  ComplianceAlert,
  ComplianceRecord,
  SignBaaRequest,
  UpdateComplianceRequest,
} from '../types/complianceApiTypes';

// Backend compliance + BAA + audit — wemarketplus-backend/src/compliance, baa, audit.
//   GET /compliance, GET /compliance/check-alerts, PATCH /compliance/:id,
//   GET /baa, POST /baa/sign, GET /audit (+ /audit/export via utils/auditExportUrl).
// NOTE: backend compliance is grant application-compliance (training reports),
// a different model from the HIPAA compliance portal pages. Wired for future
// use; the portal pages stay as-is for now.
export const complianceApi = createApi({
  reducerPath: 'complianceApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['Compliance', 'Baa', 'Audit'],
  endpoints: (build) => ({
    listCompliance: build.query<ComplianceRecord[], void>({
      query: () => ({ url: '/compliance' }),
      transformResponse: (res: ApiEnvelope<{ data: ComplianceRecord[] }>) => res.data.data,
      providesTags: ['Compliance'],
    }),
    checkAlerts: build.query<ComplianceAlert[], void>({
      query: () => ({ url: '/compliance/check-alerts' }),
      transformResponse: (res: ApiEnvelope<{ alerts: ComplianceAlert[] }>) => res.data.alerts,
      providesTags: ['Compliance'],
    }),
    updateCompliance: build.mutation<ComplianceRecord, { id: string; patch: UpdateComplianceRequest }>({
      query: ({ id, patch }) => ({ url: `/compliance/${id}`, method: 'PATCH', body: patch }),
      transformResponse: (res: ApiEnvelope<ComplianceRecord>) => res.data,
      invalidatesTags: ['Compliance'],
    }),
    getBaa: build.query<BaaRecord, void>({
      query: () => ({ url: '/baa' }),
      transformResponse: (res: ApiEnvelope<BaaRecord>) => res.data,
      providesTags: ['Baa'],
    }),
    signBaa: build.mutation<BaaRecord, SignBaaRequest>({
      query: (body) => ({ url: '/baa/sign', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<BaaRecord>) => res.data,
      invalidatesTags: ['Baa'],
    }),
    // Audit log (admin/owner) — powers the compliance portal's Audit Log screen.
    listAuditLog: build.query<{ data: AuditLogItem[]; total: number }, { page?: number; limit?: number; action?: string; resource?: string } | void>({
      query: (params) => ({ url: '/audit', params: params ?? undefined }),
      transformResponse: (res: ApiEnvelope<{ data: AuditLogItem[]; total: number }>) => res.data,
      providesTags: ['Audit'],
    }),
  }),
});

export const {
  useListComplianceQuery,
  useCheckAlertsQuery,
  useUpdateComplianceMutation,
  useGetBaaQuery,
  useSignBaaMutation,
  useListAuditLogQuery,
} = complianceApi;
