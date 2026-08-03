import type { EntityField, EntitySelectOption } from '@/shared/ui/entity';
import type { ApplicationFormValues } from '../schema/applicationSchema';

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

export const APPLICATIONS_PAGE_SIZE = 20;

// Title Case labels for the status enum values.
export const APPLICATION_STATUS_LABELS: Record<ApplicationStatus, string> = {
  draft: 'Draft',
  submitted: 'Submitted',
  under_review: 'Under review',
  approved: 'Approved',
  denied: 'Denied',
  withdrawn: 'Withdrawn',
  awarded: 'Awarded',
  active: 'Active',
  completed: 'Completed',
  closed: 'Closed',
};

const STATUS_OPTIONS: ReadonlyArray<EntitySelectOption> = [
  { value: '', label: 'Select status…' },
  ...Object.values(APPLICATION_STATUS).map((v) => ({ value: v, label: APPLICATION_STATUS_LABELS[v] })),
];

// Reference identifiers (companyId, wibId) are required and only settable at
// creation — the backend update whitelist rejects them. So the create and edit
// forms differ: create collects the references; edit collects the decision
// fields (approved amount, decision date) instead.
export const APPLICATION_CREATE_FIELDS: ReadonlyArray<EntityField<ApplicationFormValues>> = [
  // Record references, chosen from a list. These were "paste the UUID" boxes.
  { name: 'companyId', label: 'Company', type: 'lookup', full: true, placeholder: 'Select a company…' },
  { name: 'wibId', label: 'WIB', type: 'lookup', full: true, placeholder: 'Select a WIB…' },
  { name: 'fundingOpportunityId', label: 'Funding opportunity', type: 'lookup', full: true, placeholder: 'No funding opportunity' },
  { name: 'status', label: 'Status', type: 'select', options: STATUS_OPTIONS },
  { name: 'awardAmountRequested', label: 'Award requested', type: 'number', placeholder: '0' },
  { name: 'submissionDate', label: 'Submission date', placeholder: 'YYYY-MM-DD' },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true },
];

export const APPLICATION_EDIT_FIELDS: ReadonlyArray<EntityField<ApplicationFormValues>> = [
  { name: 'status', label: 'Status', type: 'select', options: STATUS_OPTIONS },
  { name: 'awardAmountRequested', label: 'Award requested', type: 'number', placeholder: '0' },
  { name: 'awardAmountApproved', label: 'Award approved', type: 'number', placeholder: '0' },
  { name: 'submissionDate', label: 'Submission date', placeholder: 'YYYY-MM-DD' },
  { name: 'decisionDate', label: 'Decision date', placeholder: 'YYYY-MM-DD' },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true },
];
