import type { ReactNode } from 'react';

export interface AuditLogEntry {
  id: string;
  /** Display name of the actor, e.g. "Admin User" / "System". */
  actor: string;
  /** Actor's email, shown under the name. Null for system rows. */
  actorEmail: string | null;
  /** Retained for filtering and for support to correlate against the API. */
  actorId: string | null;
  action: string;
  resource: string;
  target: string;
  meta: string;
  occurredAt: string;
  ipAddress: string;
}

// Structured, server-driven audit filters (mirrors the backend QueryAuditDto).
// Empty strings mean "no filter" and are stripped before the request.
export interface AuditLogFilters {
  action: string;
  resource: string;
  userId: string;
  dateFrom: string;
  dateTo: string;
}

export interface ComplianceUiState {
  // Free-text search retained for the toolbar; applied client-side over the
  // current page. Structured filters + pagination drive the server query.
  query: string;
  filters: AuditLogFilters;
  page: number;
}

// --- Compliance Portal (ported from wemarketplus-site/compliance) ---------

export type ComplianceScreen =
  | 'readiness'
  | 'audit'
  | 'access-review'
  | 'dr-test'
  | 'breach'
  | 'evidence'
  | 'baa-records'
  | 'threat-monitor';

export type ControlStatus = 'compliant' | 'partial' | 'at-risk';

export interface ReadinessControl {
  control: string;
  weight: number;
  achieved: number;
  status: ControlStatus;
  evidence: string;
}

export interface ReadinessScore {
  score: number;
  rating: string;
  status: 'audit-ready' | 'needs-remediation';
  controls: readonly ReadinessControl[];
}

export interface BaaRecord {
  id: string;
  organization: string;
  signer: string;
  signedAt: string;
  status: 'active' | 'pending';
}

export interface ThreatMetric {
  label: string;
  value: string;
  tone: 'b' | 'y' | 'r' | 'g';
}

export interface SecurityEvent {
  id: string;
  occurredAt: string;
  type: string;
  detail: string;
  risk: 'critical' | 'high' | 'medium' | 'low';
}

// --- Portal nav (moved from constants/portalContent.ts) ---

export interface PortalNavItem {
  screen: ComplianceScreen;
  to: string;
  label: string;
  group: 'Assessment' | 'Operations' | 'Evidence' | 'Security';
}

// --- Component prop types ---

export interface AuditLogTableProps {
  entries: readonly AuditLogEntry[];
  loading?: boolean;
  empty?: string;
}

export interface PortalShellProps {
  title: string;
  description: string;
  children: ReactNode;
}

export interface BaaRecordsTableProps {
  records: readonly BaaRecord[];
}
