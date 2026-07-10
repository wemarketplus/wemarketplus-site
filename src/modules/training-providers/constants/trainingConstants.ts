import type { EntityField, EntitySelectOption } from '@/shared/ui/entity';
import type { TrainingProviderFormValues } from '../schema/trainingProviderSchema';

// Training provider + roster status enums — mirror backend constants.
export const TRAINING_PROVIDER_STATUS = {
  Active: 'active',
  Inactive: 'inactive',
} as const;
export type TrainingProviderStatus =
  (typeof TRAINING_PROVIDER_STATUS)[keyof typeof TRAINING_PROVIDER_STATUS];

export const TRAINING_PROVIDERS_PAGE_SIZE = 20;

// Human labels for the provider status enum.
export const TRAINING_PROVIDER_STATUS_LABELS: Record<TrainingProviderStatus, string> = {
  active: 'Active',
  inactive: 'Inactive',
};

// Options for the status <select> in the form (leading blank = "unset").
export const TRAINING_PROVIDER_STATUS_OPTIONS: ReadonlyArray<EntitySelectOption> = [
  { value: '', label: 'Select status…' },
  ...Object.values(TRAINING_PROVIDER_STATUS).map((v) => ({
    value: v,
    label: TRAINING_PROVIDER_STATUS_LABELS[v],
  })),
];

// Field descriptors driving the create/edit modal (EntityFormModal).
export const TRAINING_PROVIDER_FIELDS: ReadonlyArray<EntityField<TrainingProviderFormValues>> = [
  { name: 'name', label: 'Provider name', full: true, placeholder: 'Acme Training Institute' },
  { name: 'status', label: 'Status', type: 'select', options: TRAINING_PROVIDER_STATUS_OPTIONS },
  { name: 'providerType', label: 'Provider type', placeholder: 'apprenticeship, college…' },
  { name: 'contactEmail', label: 'Contact email', type: 'email', placeholder: 'info@acme.org' },
  { name: 'contactPhone', label: 'Contact phone', type: 'tel', placeholder: '(555) 123-4567' },
  { name: 'website', label: 'Website', placeholder: 'https://acme.org' },
  { name: 'state', label: 'State', placeholder: 'TX' },
  { name: 'programs', label: 'Programs', type: 'textarea', full: true, placeholder: 'Welding, HVAC…' },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true },
];

export const COMPLETION_STATUS = {
  Enrolled: 'enrolled',
  InProgress: 'in_progress',
  Completed: 'completed',
  Withdrawn: 'withdrawn',
  Failed: 'failed',
} as const;
export type CompletionStatus = (typeof COMPLETION_STATUS)[keyof typeof COMPLETION_STATUS];
