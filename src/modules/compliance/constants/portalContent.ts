// Compliance Portal fixtures + nav, ported from wemarketplus-site/compliance.
// The demo-mode readiness payload in the source is reproduced verbatim.
import type {
  BaaRecord,
  PortalNavItem,
  ReadinessScore,
} from '../types/complianceTypes';

export const PORTAL_NAV: readonly PortalNavItem[] = [
  { screen: 'readiness', to: '/compliance/readiness', label: 'HIPAA Readiness', group: 'Assessment' },
  { screen: 'audit', to: '/compliance/audit', label: 'Audit Log', group: 'Assessment' },
  { screen: 'access-review', to: '/compliance/access-review', label: 'Access Review', group: 'Operations' },
  { screen: 'dr-test', to: '/compliance/dr-test', label: 'DR Test', group: 'Operations' },
  { screen: 'breach', to: '/compliance/breach', label: 'Breach Workflow', group: 'Operations' },
  { screen: 'evidence', to: '/compliance/evidence', label: 'Evidence Export', group: 'Evidence' },
  { screen: 'baa-records', to: '/compliance/baa-records', label: 'BAA Records', group: 'Evidence' },
  { screen: 'threat-monitor', to: '/compliance/threat-monitor', label: 'Threat Monitor', group: 'Security' },
];

// Verbatim demo-mode readiness from the source.
export const READINESS_FIXTURE: ReadinessScore = {
  score: 72,
  rating: 'B',
  status: 'needs-remediation',
  controls: [
    { control: 'Business Associate Agreement', weight: 10, achieved: 10, status: 'compliant', evidence: 'Signed at onboarding' },
    { control: 'Audit Log Monitoring', weight: 15, achieved: 10, status: 'partial', evidence: '47 audit events in last 30 days' },
    { control: 'Role-Based Access Control', weight: 15, achieved: 15, status: 'compliant', evidence: '2 admins, 4 total users' },
    { control: 'User Access Reviews', weight: 10, achieved: 5, status: 'at-risk', evidence: '1 user inactive 90+ days' },
    { control: 'PHI Access Logging', weight: 15, achieved: 15, status: 'compliant', evidence: '312 PHI access events logged' },
    { control: 'Password Policy', weight: 10, achieved: 10, status: 'compliant', evidence: 'bcrypt-12, 8+ char minimum' },
    { control: 'Encryption at Rest & Transit', weight: 15, achieved: 15, status: 'compliant', evidence: 'AES-256 + TLS 1.3' },
    { control: 'Disaster Recovery Testing', weight: 10, achieved: 7, status: 'partial', evidence: 'Last DR test 40 days ago' },
  ],
};

export const BAA_RECORDS_FIXTURE: readonly BaaRecord[] = [
  { id: 'baa-1', organization: 'Bay Area Hospice Group', signer: 'Avery Cole', signedAt: '2025-03-12T00:00:00Z', status: 'active' },
  { id: 'baa-2', organization: 'Northstar Hospice', signer: 'Lana Diaz', signedAt: '2024-09-21T00:00:00Z', status: 'active' },
  { id: 'baa-3', organization: 'Pinecrest Care', signer: 'Bilal Zaman', signedAt: '2025-04-29T00:00:00Z', status: 'pending' },
];



export const BREACH_TYPES = [
  'unauthorized_phi_access',
  'ransomware',
  'employee_error',
  'vendor_breach',
  'lost_device',
  'other',
] as const;

export const GROUPS: ReadonlyArray<PortalNavItem['group']> = [
  'Assessment',
  'Operations',
  'Evidence',
  'Security',
];

export const TYPE_LABELS: Record<string, string> = {
  unauthorized_phi_access: 'Unauthorized PHI access',
  ransomware: 'Ransomware',
  employee_error: 'Employee error',
  vendor_breach: 'Vendor breach',
  lost_device: 'Lost device',
  other: 'Other',
};

// THREAT_METRICS and SECURITY_EVENTS were removed deliberately. They were invented
// figures ("Failed Logins (24h): 3", "Threat Level: Low") and three fabricated
// events with realistic email addresses, rendered as "Real-time security metrics".
// ThreatMonitorPage now reads GET /audit/threat-monitor. Do not reintroduce
// fixtures on a security screen.
