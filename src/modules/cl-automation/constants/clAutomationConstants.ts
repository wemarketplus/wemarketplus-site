// Mirrors wemarketplus-backend/src/automation-sequences/automation-sequences.constants.
// One vocabulary on both sides — the drift these mirrors prevent is the same class
// that let the calendar write a visit type the Outreach Log could never filter by.

export const SEQUENCE_TRIGGER = {
  ClLeadLost: 'cl_lead_lost',
  ClLeadInactive: 'cl_lead_inactive',
  Manual: 'manual',
} as const;
export type SequenceTrigger =
  (typeof SEQUENCE_TRIGGER)[keyof typeof SEQUENCE_TRIGGER];

export const SEQUENCE_TRIGGER_LABELS: Record<SequenceTrigger, string> = {
  [SEQUENCE_TRIGGER.ClLeadLost]: 'A lead is marked Lost',
  [SEQUENCE_TRIGGER.ClLeadInactive]: 'A lead is marked Inactive',
  [SEQUENCE_TRIGGER.Manual]: 'Nothing — start runs by hand',
};

/**
 * Only the two actions the engine can genuinely perform.
 *
 * Email and SMS are deliberately absent rather than shown disabled: the platform
 * has no SMS provider at all, the mailer has only fixed templates, and outbound
 * marketing email to families needs a consent and unsubscribe decision before a
 * single message goes out. Offering a greyed-out "Email" row would read as "coming
 * soon" for something that is a product decision, not a build queue item.
 */
export const SEQUENCE_ACTION = {
  Task: 'task',
  Notification: 'notification',
} as const;
export type SequenceAction =
  (typeof SEQUENCE_ACTION)[keyof typeof SEQUENCE_ACTION];

export const SEQUENCE_ACTION_LABELS: Record<SequenceAction, string> = {
  [SEQUENCE_ACTION.Task]: 'Create a task',
  [SEQUENCE_ACTION.Notification]: 'Notify the lead owner',
};

/** What each action actually does, shown under the picker so it is not a guess. */
export const SEQUENCE_ACTION_HINTS: Record<SequenceAction, string> = {
  [SEQUENCE_ACTION.Task]:
    'Adds a task against the lead, assigned to whoever owns it. Appears in Tasks and Daily tasks.',
  [SEQUENCE_ACTION.Notification]:
    "Sends the lead owner an in-app notification. Skipped if the lead has no owner.",
};

export const ENROLLMENT_STATUS = {
  Active: 'active',
  Completed: 'completed',
  Cancelled: 'cancelled',
} as const;
export type EnrollmentStatus =
  (typeof ENROLLMENT_STATUS)[keyof typeof ENROLLMENT_STATUS];

export const ENROLLMENT_STATUS_LABELS: Record<EnrollmentStatus, string> = {
  [ENROLLMENT_STATUS.Active]: 'Running',
  [ENROLLMENT_STATUS.Completed]: 'Finished',
  [ENROLLMENT_STATUS.Cancelled]: 'Stopped',
};

export const ENROLLMENT_STATUS_PILL: Record<
  EnrollmentStatus,
  'g' | 'b' | 'y'
> = {
  [ENROLLMENT_STATUS.Active]: 'g',
  [ENROLLMENT_STATUS.Completed]: 'b',
  [ENROLLMENT_STATUS.Cancelled]: 'y',
};

export const MAX_STEPS_PER_SEQUENCE = 20;
export const MAX_STEP_DELAY_DAYS = 365;
export const SEQUENCE_NAME_MAX_LENGTH = 200;
export const SEQUENCE_STEP_TITLE_MAX_LENGTH = 300;
export const CL_SEQUENCES_PAGE_SIZE = 20;
