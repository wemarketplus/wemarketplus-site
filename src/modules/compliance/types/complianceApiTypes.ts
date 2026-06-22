import type { ID, ISODateString } from '@/shared/types';

// Backend compliance + BAA + audit record shapes — wemarketplus-backend
// src/compliance, src/baa, src/audit. NOTE: backend compliance is grant
// application-compliance (training reports), distinct from the HIPAA portal UI.

// Mirrors ComplianceResponseDto.
export interface ComplianceRecord {
  id: ID;
  tenantId: ID;
  applicationId: ID;
  applicationNumber: string | null;
  companyName: string | null;
  wibName: string | null;
  trainingEndDate: string | null;
  finalReportDue: string | null;
  finalReportSubmitted: boolean;
  finalReportSubmittedDate: string | null;
  interimReportDue: string | null;
  interimReportSubmitted: boolean;
  attendanceSheetsCollected: boolean;
  complianceNotes: string | null;
  daysUntilFinalDue: number | null;
  daysUntilInterimDue: number | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface ComplianceAlert {
  type:
    | 'compliance_report_overdue'
    | 'compliance_report_due_soon'
    | 'interim_report_overdue'
    | 'invoice_overdue';
  severity: 'high' | 'medium' | 'low';
  recordType: 'application' | 'revenue_record';
  recordId: ID;
  companyName: string;
  applicationNumber?: string | null;
  message: string;
  daysOverdue?: number;
  daysUntilDue?: number;
  dueDate?: string | null;
}

export interface UpdateComplianceRequest {
  finalReportSubmitted?: boolean;
  finalReportSubmittedDate?: string;
  attendanceSheetsCollected?: boolean;
  complianceNotes?: string;
}

// Mirrors BaaRecordResponseDto.
export interface BaaRecord {
  id: ID;
  tenantId: ID;
  signerName: string;
  signerEmail: string;
  signedAt: ISODateString;
  plan: string | null;
  pendingFullSignature: boolean;
  createdAt: ISODateString;
}

export interface SignBaaRequest {
  signerName: string;
  signerEmail: string;
  plan?: string;
  pendingFullSignature?: boolean;
}

export interface AuditLogItem {
  id: ID;
  tenantId: ID | null;
  userId: ID | null;
  action: string;
  resource: string | null;
  resourceId: ID | null;
  meta: Record<string, unknown>;
  createdAt: ISODateString;
}
