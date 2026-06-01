import { CareLevel, LeadStatus } from '@/shared/types';

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
