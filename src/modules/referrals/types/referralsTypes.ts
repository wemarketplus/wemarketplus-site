import type { ReferralSource, ReferralSourceStatus } from '@/shared/types';

export type { ReferralSource };

export interface ReferralsUiState {
  search: string;
  statusFilter: ReferralSourceStatus | 'all';
}
