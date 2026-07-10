import type { EntityField, EntitySelectOption } from '@/shared/ui/entity';
import type { FundingFormValues } from '../schema/fundingSchema';

// Funding opportunity status — mirrors backend FundingStatus enum.
export const FUNDING_STATUS = {
  Open: 'open',
  Upcoming: 'upcoming',
  Closed: 'closed',
  Archived: 'archived',
} as const;

export type FundingStatus = (typeof FUNDING_STATUS)[keyof typeof FUNDING_STATUS];

export const FUNDING_PAGE_SIZE = 20;

// Human labels for the status enum (Title Case from the snake/lower values).
export const FUNDING_STATUS_LABELS: Record<FundingStatus, string> = {
  open: 'Open',
  upcoming: 'Upcoming',
  closed: 'Closed',
  archived: 'Archived',
};

// Options for the status <select> in the form (leading blank = "unset").
export const FUNDING_STATUS_OPTIONS: ReadonlyArray<EntitySelectOption> = [
  { value: '', label: 'Select status…' },
  ...Object.values(FUNDING_STATUS).map((v) => ({ value: v, label: FUNDING_STATUS_LABELS[v] })),
];

// Field descriptors driving the create/edit modal (EntityFormModal).
export const FUNDING_FIELDS: ReadonlyArray<EntityField<FundingFormValues>> = [
  { name: 'opportunityName', label: 'Opportunity name', full: true, placeholder: 'Workforce Innovation Grant' },
  { name: 'sourceUrl', label: 'Source URL', full: true, placeholder: 'https://grants.gov/…' },
  { name: 'status', label: 'Status', type: 'select', options: FUNDING_STATUS_OPTIONS },
  { name: 'programType', label: 'Program type', placeholder: 'IWT, apprenticeship…' },
  { name: 'maxAwardPerEin', label: 'Max award per EIN', type: 'number', placeholder: '0' },
  { name: 'applicationDeadline', label: 'Application deadline', type: 'text', placeholder: 'YYYY-MM-DD' },
  { name: 'applicationLink', label: 'Application link', full: true, placeholder: 'https://…' },
  { name: 'wibId', label: 'WIB id (UUID)', full: true, placeholder: 'optional, set at creation only' },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true },
];
