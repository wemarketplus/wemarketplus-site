// Suggested pipeline stages for the owner-portal sales board. The backend
// stores `stage` as a free-form string (default "Lead"), so these are the
// stages the create/edit form offers, and the board renders any additional
// stages returned by the API under an "Other" column.
export const OWNER_PIPELINE_STAGES = [
  'Lead',
  'Qualified',
  'Demo',
  'Proposal',
  'Won',
  'Lost',
] as const;
