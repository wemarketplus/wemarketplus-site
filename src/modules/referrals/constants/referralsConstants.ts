import { ReferralSourceStatus } from '@/shared/types';
import type { PillProps } from '@/shared/ui/data-display';
import { ReferralSourceType } from '../types/referralsTypes';
import type { ReferralFilterChip } from '../types/referralsTypes';

export const REFERRALS_TAGS = {
  List: 'Referrals.List',
  Detail: 'Referrals.Detail',
} as const;

export const REFERRAL_STATUS_LABELS: Record<ReferralSourceStatus, string> = {
  [ReferralSourceStatus.Green]: 'Green',
  [ReferralSourceStatus.Building]: 'Building',
  [ReferralSourceStatus.Red]: 'Red',
};

export const STATUS_PILL: Record<ReferralSourceStatus, PillProps['tone']> = {
  [ReferralSourceStatus.Green]: 'g',
  [ReferralSourceStatus.Building]: 'y',
  [ReferralSourceStatus.Red]: 'r',
};

export const REFERRAL_FILTER_CHIPS: ReadonlyArray<ReferralFilterChip> = [
  { value: 'all', label: 'All statuses' },
  { value: ReferralSourceStatus.Green, label: REFERRAL_STATUS_LABELS.green },
  { value: ReferralSourceStatus.Building, label: REFERRAL_STATUS_LABELS.building },
  { value: ReferralSourceStatus.Red, label: REFERRAL_STATUS_LABELS.red },
];

// Select options for the Add-referral-source form (backend type enum).
export const REFERRAL_TYPE_OPTIONS: ReadonlyArray<{
  value: ReferralSourceType;
  label: string;
}> = [
  { value: ReferralSourceType.Hospital, label: 'Hospital' },
  { value: ReferralSourceType.SkilledNursing, label: 'Skilled nursing' },
  { value: ReferralSourceType.AssistedLiving, label: 'Assisted living' },
  { value: ReferralSourceType.Physician, label: 'Physician' },
  { value: ReferralSourceType.HomeHealth, label: 'Home health' },
  { value: ReferralSourceType.Icu, label: 'ICU' },
  { value: ReferralSourceType.MemoryCare, label: 'Memory care' },
  { value: ReferralSourceType.Facility, label: 'Facility' },
  { value: ReferralSourceType.Other, label: 'Other' },
];
