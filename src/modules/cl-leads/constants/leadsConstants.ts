import { CareLevel, LeadStatus } from '@/shared/types';
import type { PillProps } from '@/shared/ui/data-display';

export const CARE_LEVEL_LABELS: Record<CareLevel, string> = {
  [CareLevel.IL]: 'Independent Living',
  [CareLevel.AL]: 'Assisted Living',
  [CareLevel.MC]: 'Memory Care',
};

export const LEAD_STATUS_LABELS: Record<LeadStatus, string> = {
  [LeadStatus.Inquiry]: 'Inquiry',
  [LeadStatus.TourScheduled]: 'Tour scheduled',
  [LeadStatus.Proposal]: 'Proposal',
  [LeadStatus.FollowUp]: 'Follow-up',
  [LeadStatus.MoveIn]: 'Move-in',
  [LeadStatus.Lost]: 'Lost',
};

export const STATUS_PILL: Record<LeadStatus, PillProps['tone']> = {
  [LeadStatus.Inquiry]: 'b',
  [LeadStatus.TourScheduled]: 'p',
  [LeadStatus.Proposal]: 'y',
  [LeadStatus.FollowUp]: 'b',
  [LeadStatus.MoveIn]: 'g',
  [LeadStatus.Lost]: 'r',
};

export const CHIPS: ReadonlyArray<{ value: LeadStatus | 'all'; label: string }> = [
  { value: 'all', label: 'All' },
  ...Object.values(LeadStatus).map((s) => ({
    value: s as LeadStatus,
    label: LEAD_STATUS_LABELS[s],
  })),
];
