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
  /**
   * Resolved display name of the acting user. The backend has always sent this
   * (AuditLogResponseDto joins the actor), but the client only read `userId` —
   * so a compliance screen whose job is to answer "who did this" was rendering
   * raw uuids. "System" for cron/webhook-written rows, "Unknown user" when the
   * account has since been hard-deleted.
   */
  actorName: string;
  /** Null for system rows and for actors that no longer resolve. */
  actorEmail: string | null;
  action: string;
  resource: string | null;
  resourceId: ID | null;
  meta: Record<string, unknown>;
  createdAt: ISODateString;
}

// Query params for GET /audit — mirrors QueryAuditDto on the backend. All
// filters are optional; dateFrom/dateTo are ISO 8601 (date or datetime).
export interface AuditLogQuery {
  page?: number;
  limit?: number;
  action?: string;
  resource?: string;
  userId?: string;
  resourceId?: string;
  dateFrom?: string;
  dateTo?: string;
}

/** A Threat Monitor tile. `value` is null when the input is not collected. */
export interface ThreatMetric {
  label: string;
  value: string | null;
  tone: 'g' | 'y' | 'r';
  /** Present when the metric cannot be computed, so the UI can say why. */
  unavailableReason?: string;
}

export interface ThreatSecurityEvent {
  id: string;
  type: string;
  detail: string;
  risk: 'low' | 'medium' | 'high';
  occurredAt: string;
}

export interface ThreatMonitorSummary {
  metrics: ThreatMetric[];
  events: ThreatSecurityEvent[];
}
