import { ReferralSourceStatus } from '@/shared/types';
import type { PillProps } from '@/shared/ui/data-display';
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
