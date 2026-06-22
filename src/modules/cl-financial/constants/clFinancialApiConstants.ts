// Backend CommunityLink concession status — mirrors wemarketplus-backend
// communitylink.constants ConcessionStatus.
export const CONCESSION_STATUS = {
  Pending: 'pending',
  Approved: 'approved',
  Rejected: 'rejected',
} as const;

export type ConcessionStatus = (typeof CONCESSION_STATUS)[keyof typeof CONCESSION_STATUS];
