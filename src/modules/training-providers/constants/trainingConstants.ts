// Training provider + roster status enums — mirror backend constants.
export const TRAINING_PROVIDER_STATUS = {
  Active: 'active',
  Inactive: 'inactive',
} as const;
export type TrainingProviderStatus =
  (typeof TRAINING_PROVIDER_STATUS)[keyof typeof TRAINING_PROVIDER_STATUS];

export const COMPLETION_STATUS = {
  Enrolled: 'enrolled',
  InProgress: 'in_progress',
  Completed: 'completed',
  Withdrawn: 'withdrawn',
  Failed: 'failed',
} as const;
export type CompletionStatus = (typeof COMPLETION_STATUS)[keyof typeof COMPLETION_STATUS];
