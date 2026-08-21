import type { PillProps } from '@/shared/ui/data-display';
import type { EntityField, EntitySelectOption } from '@/shared/ui/entity';
import {
  CL_CARE_LEVEL,
  CL_URGENCY,
  FEE_STATUS,
  type FeeStatus,
  type ClUrgency,
} from './clReferralsApiConstants';
import type { PaidReferralFormValues } from '../schema/paidReferralSchema';

export const PAID_REFERRALS_PAGE_SIZE = 20;

export const FEE_STATUS_LABELS: Record<FeeStatus, string> = {
  [FEE_STATUS.Pending]: 'Pending',
  [FEE_STATUS.Paid]: 'Paid',
  [FEE_STATUS.Waived]: 'Waived',
  [FEE_STATUS.NotApplicable]: 'Organic',
};

export const FEE_STATUS_PILL: Record<FeeStatus, PillProps['tone']> = {
  [FEE_STATUS.Pending]: 'y',
  [FEE_STATUS.Paid]: 'g',
  [FEE_STATUS.Waived]: 'b',
  [FEE_STATUS.NotApplicable]: 'b',
};

export const URGENCY_LABELS: Record<ClUrgency, string> = {
  // High / Medium / Low, not Hot / Warm / Cold — see the note on
  // shared/constants/urgencyConstants.ts. The wire values are unchanged.
  [CL_URGENCY.Hot]: 'High',
  [CL_URGENCY.Warm]: 'Medium',
  [CL_URGENCY.Cold]: 'Low',
};

export const URGENCY_PILL: Record<ClUrgency, PillProps['tone']> = {
  [CL_URGENCY.Hot]: 'r',
  [CL_URGENCY.Warm]: 'y',
  [CL_URGENCY.Cold]: 'b',
};

const toOptions = (labels: Record<string, string>): readonly EntitySelectOption[] =>
  Object.entries(labels).map(([value, label]) => ({ value, label }));

export const FEE_STATUS_OPTIONS = toOptions(FEE_STATUS_LABELS);
export const PR_URGENCY_OPTIONS = toOptions(URGENCY_LABELS);
export const CARE_LEVEL_OPTIONS: readonly EntitySelectOption[] = [
  { value: CL_CARE_LEVEL.IndependentLiving, label: 'Independent Living' },
  { value: CL_CARE_LEVEL.AssistedLiving, label: 'Assisted Living' },
  { value: CL_CARE_LEVEL.MemoryCare, label: 'Memory Care' },
];

// Create/edit form field descriptors.
export const PAID_REFERRAL_FIELDS: ReadonlyArray<EntityField<PaidReferralFormValues>> = [
  { name: 'prospectName', label: 'Prospect name', placeholder: 'Dorothy Harrison' },
  { name: 'prospectPhone', label: 'Prospect phone', type: 'tel', placeholder: '(214) 555-0100' },
  { name: 'careLevel', label: 'Care level', type: 'select', options: CARE_LEVEL_OPTIONS },
  { name: 'urgency', label: 'Urgency', type: 'select', options: PR_URGENCY_OPTIONS },
  { name: 'sourceName', label: 'Referral source', placeholder: 'A Place for Mom' },
  { name: 'referralFee', label: 'Referral fee', type: 'text', placeholder: '3500' },
  { name: 'feeStatus', label: 'Fee status', type: 'select', options: FEE_STATUS_OPTIONS },
  { name: 'stage', label: 'Stage', placeholder: 'New Referral' },
];
