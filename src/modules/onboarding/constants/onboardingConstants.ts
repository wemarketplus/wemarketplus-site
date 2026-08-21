import type { OnboardingStep } from '../types/onboardingTypes';

// Draft persistence — mirrors the 2-hour window from the site's onboard.html.
export const ONBOARDING_DRAFT_KEY = 'wemarketplus.onboarding.draft';
export const ONBOARDING_DRAFT_TTL_MS = 2 * 60 * 60 * 1000;

export const STEP_ORDER: readonly OnboardingStep[] = [
  'account',
  'agency',
  'baa',
  'launch',
];

export const STEP_LABELS: Record<OnboardingStep, string> = {
  account: 'Account info',
  agency: 'Agency info',
  baa: 'Business agreement',
  launch: 'Launch',
};

// US state list — kept here so the AgencyInfo step doesn't pull in a large
// shared list module. Trim to the values the site dropdown actually uses.
export const US_STATES: readonly { value: string; label: string }[] = [
  { value: 'AL', label: 'Alabama' },
  { value: 'AK', label: 'Alaska' },
  { value: 'AZ', label: 'Arizona' },
  { value: 'AR', label: 'Arkansas' },
  { value: 'CA', label: 'California' },
  { value: 'CO', label: 'Colorado' },
  { value: 'CT', label: 'Connecticut' },
  { value: 'DE', label: 'Delaware' },
  { value: 'FL', label: 'Florida' },
  { value: 'GA', label: 'Georgia' },
  { value: 'HI', label: 'Hawaii' },
  { value: 'ID', label: 'Idaho' },
  { value: 'IL', label: 'Illinois' },
  { value: 'IN', label: 'Indiana' },
  { value: 'IA', label: 'Iowa' },
  { value: 'KS', label: 'Kansas' },
  { value: 'KY', label: 'Kentucky' },
  { value: 'LA', label: 'Louisiana' },
  { value: 'ME', label: 'Maine' },
  { value: 'MD', label: 'Maryland' },
  { value: 'MA', label: 'Massachusetts' },
  { value: 'MI', label: 'Michigan' },
  { value: 'MN', label: 'Minnesota' },
  { value: 'MS', label: 'Mississippi' },
  { value: 'MO', label: 'Missouri' },
  { value: 'MT', label: 'Montana' },
  { value: 'NE', label: 'Nebraska' },
  { value: 'NV', label: 'Nevada' },
  { value: 'NH', label: 'New Hampshire' },
  { value: 'NJ', label: 'New Jersey' },
  { value: 'NM', label: 'New Mexico' },
  { value: 'NY', label: 'New York' },
  { value: 'NC', label: 'North Carolina' },
  { value: 'ND', label: 'North Dakota' },
  { value: 'OH', label: 'Ohio' },
  { value: 'OK', label: 'Oklahoma' },
  { value: 'OR', label: 'Oregon' },
  { value: 'PA', label: 'Pennsylvania' },
  { value: 'RI', label: 'Rhode Island' },
  { value: 'SC', label: 'South Carolina' },
  { value: 'SD', label: 'South Dakota' },
  { value: 'TN', label: 'Tennessee' },
  { value: 'TX', label: 'Texas' },
  { value: 'UT', label: 'Utah' },
  { value: 'VT', label: 'Vermont' },
  { value: 'VA', label: 'Virginia' },
  { value: 'WA', label: 'Washington' },
  { value: 'WV', label: 'West Virginia' },
  { value: 'WI', label: 'Wisconsin' },
  { value: 'WY', label: 'Wyoming' },
  { value: 'DC', label: 'Washington, D.C.' },
];

/**
 * US_STATES shaped for <ListboxSelect>: the two-letter code is the label (it is
 * what the field stores and what both forms have always displayed) and the full
 * state name rides along as the hint.
 *
 * The name was previously unreachable — the native <select> rendered `s.value`
 * for every option, so the list read "AL, AK, AZ…" and picking the right one
 * meant knowing the abbreviation. It costs nothing to show both now that we draw
 * the list ourselves, and type-ahead matches either, so "mary" reaches MD.
 */
export const US_STATE_OPTIONS: readonly {
  value: string;
  label: string;
  hint: string;
}[] = US_STATES.map((s) => ({ value: s.value, label: s.value, hint: s.label }));
