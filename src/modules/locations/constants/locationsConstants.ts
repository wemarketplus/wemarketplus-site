// Employer location status — mirrors backend LocationStatus enum.
export const LOCATION_STATUS = {
  Active: 'active',
  Inactive: 'inactive',
  Prospect: 'prospect',
} as const;

export type LocationStatus = (typeof LOCATION_STATUS)[keyof typeof LOCATION_STATUS];
