import type { AuditLogEntry } from '../types/complianceTypes';

// Audit log fixture — same shape as owner-portal's audit table; module-local
// so HIPAA-specific filtering can evolve independently.
export const AUDIT_FIXTURE: readonly AuditLogEntry[] = [
  {
    id: 'au-001',
    actor: 'avery@bahg.org',
    action: 'Viewed PHI',
    target: 'Eleanor Whitmore',
    occurredAt: '2026-05-24T17:10:00Z',
    ipAddress: '203.0.113.18',
  },
  {
    id: 'au-002',
    actor: 'jordan@bahg.org',
    action: 'Updated prospect',
    target: 'Hector Alvarez',
    occurredAt: '2026-05-24T16:48:00Z',
    ipAddress: '198.51.100.23',
  },
  {
    id: 'au-003',
    actor: 'avery@bahg.org',
    action: 'Exported HIPAA log',
    target: 'May 2026 bundle',
    occurredAt: '2026-05-23T17:30:00Z',
    ipAddress: '203.0.113.18',
  },
  {
    id: 'au-004',
    actor: 'system',
    action: 'Background encryption rotation',
    target: 'tenant:bahg',
    occurredAt: '2026-05-23T04:00:00Z',
    ipAddress: '127.0.0.1',
  },
];
