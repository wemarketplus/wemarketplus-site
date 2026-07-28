// Backend CommunityLink concession status — mirrors wemarketplus-backend
// communitylink.constants ConcessionStatus.
export const CONCESSION_STATUS = {
  Pending: 'pending',
  Approved: 'approved',
  Rejected: 'rejected',
} as const;

export type ConcessionStatus = (typeof CONCESSION_STATUS)[keyof typeof CONCESSION_STATUS];

// Backend CommunityLink revenue-leakage status — mirrors wemarketplus-backend
// communitylink.constants LeakageStatus.
export const LEAKAGE_STATUS = {
  Active: 'active',
  Ongoing: 'ongoing',
  Review: 'review',
  FixNeeded: 'fix_needed',
  Resolved: 'resolved',
} as const;

export type LeakageStatus = (typeof LEAKAGE_STATUS)[keyof typeof LEAKAGE_STATUS];
