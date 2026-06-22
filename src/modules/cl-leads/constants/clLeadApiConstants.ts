// Backend CommunityLink lead enums — mirror wemarketplus-backend
// communitylink.constants (CareLevel, LeadStage, Urgency). Distinct from the
// UI-layer LeadStatus in @/shared/types (see leadsConstants for the display map).
export const CL_CARE_LEVEL = {
  IndependentLiving: 'IL',
  AssistedLiving: 'AL',
  MemoryCare: 'MC',
} as const;
export type ClCareLevel = (typeof CL_CARE_LEVEL)[keyof typeof CL_CARE_LEVEL];

export const CL_LEAD_STAGE = {
  Inquiry: 'inquiry',
  Contacted: 'contacted',
  TourScheduled: 'tour_scheduled',
  Toured: 'toured',
  ProposalSent: 'proposal_sent',
  DepositPaid: 'deposit_paid',
  MovedIn: 'moved_in',
  Lost: 'lost',
  Inactive: 'inactive',
} as const;
export type ClLeadStage = (typeof CL_LEAD_STAGE)[keyof typeof CL_LEAD_STAGE];

export const CL_URGENCY = {
  Hot: 'hot',
  Warm: 'warm',
  Cold: 'cold',
} as const;
export type ClUrgency = (typeof CL_URGENCY)[keyof typeof CL_URGENCY];
