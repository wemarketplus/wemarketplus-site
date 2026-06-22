// Workforce Investment Board status — mirrors backend WibStatus enum.
export const WIB_STATUS = {
  New: 'new',
  Researching: 'researching',
  Contacted: 'contacted',
  InDiscussion: 'in_discussion',
  Active: 'active',
  Inactive: 'inactive',
  Declined: 'declined',
} as const;

export type WibStatus = (typeof WIB_STATUS)[keyof typeof WIB_STATUS];
