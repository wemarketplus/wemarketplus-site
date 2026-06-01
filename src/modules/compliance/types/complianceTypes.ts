export interface AuditLogEntry {
  id: string;
  actor: string;
  action: string;
  target: string;
  occurredAt: string;
  ipAddress: string;
}

export interface ComplianceUiState {
  query: string;
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
