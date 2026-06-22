// Employer company status — mirrors backend CompanyStatus enum.
export const COMPANY_STATUS = {
  Prospect: 'prospect',
  Contacted: 'contacted',
  Engaged: 'engaged',
  Active: 'active',
  Inactive: 'inactive',
  Declined: 'declined',
} as const;

export type CompanyStatus = (typeof COMPANY_STATUS)[keyof typeof COMPANY_STATUS];
