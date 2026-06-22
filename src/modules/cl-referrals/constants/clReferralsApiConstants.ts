// Backend CommunityLink referral enums — mirror wemarketplus-backend
// communitylink.constants (CareLevel, Urgency, FeeStatus).
export const CL_CARE_LEVEL = {
  IndependentLiving: 'IL',
  AssistedLiving: 'AL',
  MemoryCare: 'MC',
} as const;
export type ClCareLevel = (typeof CL_CARE_LEVEL)[keyof typeof CL_CARE_LEVEL];

export const CL_URGENCY = {
  Hot: 'hot',
  Warm: 'warm',
  Cold: 'cold',
} as const;
export type ClUrgency = (typeof CL_URGENCY)[keyof typeof CL_URGENCY];

export const FEE_STATUS = {
  Pending: 'pending',
  Paid: 'paid',
  Waived: 'waived',
  NotApplicable: 'na',
} as const;
export type FeeStatus = (typeof FEE_STATUS)[keyof typeof FEE_STATUS];
