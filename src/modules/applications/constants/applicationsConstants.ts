// Application status — mirrors backend ApplicationStatus enum.
export const APPLICATION_STATUS = {
  Draft: 'draft',
  Submitted: 'submitted',
  UnderReview: 'under_review',
  Approved: 'approved',
  Denied: 'denied',
  Withdrawn: 'withdrawn',
  Awarded: 'awarded',
  Active: 'active',
  Completed: 'completed',
  Closed: 'closed',
} as const;

export type ApplicationStatus = (typeof APPLICATION_STATUS)[keyof typeof APPLICATION_STATUS];
