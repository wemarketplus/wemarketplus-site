// Funding opportunity status — mirrors backend FundingStatus enum.
export const FUNDING_STATUS = {
  Open: 'open',
  Upcoming: 'upcoming',
  Closed: 'closed',
  Archived: 'archived',
} as const;

export type FundingStatus = (typeof FUNDING_STATUS)[keyof typeof FUNDING_STATUS];
