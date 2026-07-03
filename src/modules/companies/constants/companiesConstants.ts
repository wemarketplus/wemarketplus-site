import type { EntityField, EntitySelectOption } from '@/shared/ui/entity';
import type { PillProps } from '@/shared/ui/data-display';
import type { CompanyFormValues } from '../schema/companySchema';

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

export const COMPANIES_PAGE_SIZE = 20;

export const COMPANY_STATUS_LABELS: Record<CompanyStatus, string> = {
  [COMPANY_STATUS.Prospect]: 'Prospect',
  [COMPANY_STATUS.Contacted]: 'Contacted',
  [COMPANY_STATUS.Engaged]: 'Engaged',
  [COMPANY_STATUS.Active]: 'Active',
  [COMPANY_STATUS.Inactive]: 'Inactive',
  [COMPANY_STATUS.Declined]: 'Declined',
};

// Pill tone per status (see shared Pill tones: g/b/r/y/p/gd).
export const COMPANY_STATUS_PILL: Record<CompanyStatus, NonNullable<PillProps['tone']>> = {
  [COMPANY_STATUS.Prospect]: 'b',
  [COMPANY_STATUS.Contacted]: 'y',
  [COMPANY_STATUS.Engaged]: 'p',
  [COMPANY_STATUS.Active]: 'g',
  [COMPANY_STATUS.Inactive]: 'r',
  [COMPANY_STATUS.Declined]: 'r',
};

const STATUS_OPTIONS: readonly EntitySelectOption[] = Object.values(COMPANY_STATUS).map(
  (value) => ({ value, label: COMPANY_STATUS_LABELS[value] }),
);

// Status options including a blank leading entry for the filter dropdown.
export const COMPANY_STATUS_FILTER_OPTIONS: readonly EntitySelectOption[] = [
  { value: '', label: 'All statuses' },
  ...STATUS_OPTIONS,
];

// Field descriptors driving the create/edit modal (EntityFormModal).
export const COMPANY_FIELDS: ReadonlyArray<EntityField<CompanyFormValues>> = [
  { name: 'companyName', label: 'Company name', full: true, placeholder: 'Acme Manufacturing' },
  { name: 'status', label: 'Status', type: 'select', options: STATUS_OPTIONS },
  { name: 'companyType', label: 'Company type', placeholder: 'Employer, staffing…' },
  { name: 'industry', label: 'Industry', placeholder: 'Manufacturing' },
  { name: 'naicsCode', label: 'NAICS code', placeholder: '336111' },
  { name: 'fein', label: 'FEIN', placeholder: '12-3456789' },
  { name: 'employeeCountTotal', label: 'Employees (total)', type: 'number' },
  { name: 'domain', label: 'Domain', placeholder: 'acme.com' },
  { name: 'website', label: 'Website', placeholder: 'https://acme.com' },
  { name: 'primaryContactName', label: 'Primary contact', placeholder: 'Jane Doe' },
  { name: 'primaryContactEmail', label: 'Contact email', type: 'email' },
  { name: 'primaryContactPhone', label: 'Contact phone', type: 'tel' },
  { name: 'trainingNeeds', label: 'Training needs', type: 'textarea', full: true },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true },
];
