import { ReferralSourceStatus } from '@/shared/types';

export const REFERRALS_TAGS = {
  List: 'Referrals.List',
  Detail: 'Referrals.Detail',
} as const;

export const REFERRAL_STATUS_LABELS: Record<ReferralSourceStatus, string> = {
  [ReferralSourceStatus.Green]: 'Green',
  [ReferralSourceStatus.Building]: 'Building',
  [ReferralSourceStatus.Red]: 'Red',
};
