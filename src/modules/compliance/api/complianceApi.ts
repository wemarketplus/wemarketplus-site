import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type {
  AuditLogItem,
  AuditLogQuery,
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
// Drops undefined/empty values so a cleared filter never lands in the query
// string (backend @IsUUID/@IsISO8601 would 400 on an empty string).
function stripEmpty(
  params: AuditLogQuery | void,
): Record<string, string | number> | undefined {
  if (!params) return undefined;
  const out: Record<string, string | number> = {};
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      out[key] = value as string | number;
    }
  }
  return out;
}

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
    // Server-side pagination + filtering (action, resource, actor userId,
    // affected resourceId, ISO date range). Empty-string params are stripped so
    // a cleared filter drops out of the query string rather than matching "".
    listAuditLog: build.query<{ data: AuditLogItem[]; total: number }, AuditLogQuery | void>({
      query: (params) => ({ url: '/audit', params: stripEmpty(params) }),
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
