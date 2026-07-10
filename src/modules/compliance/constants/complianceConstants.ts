import type { ControlStatus, SecurityEvent } from '../types/complianceTypes';
import type { PillProps } from '@/shared/ui/data-display';

// Page size for the server-driven audit log viewer (GET /audit). Kept below the
// backend MAX_LIMIT (100).
export const AUDIT_PAGE_SIZE = 25;

export const STATUS_PILL: Record<ControlStatus, PillProps['tone']> = {
  compliant: 'g',
  partial: 'y',
  'at-risk': 'r',
};

export const STATUS_LABEL: Record<ControlStatus, string> = {
  compliant: 'Compliant',
  partial: 'Partial',
  'at-risk': 'At risk',
};

export const RISK_PILL: Record<SecurityEvent['risk'], PillProps['tone']> = {
  critical: 'r',
  high: 'r',
  medium: 'y',
  low: 'b',
};
