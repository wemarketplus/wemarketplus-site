import type { ReferralSourceStatus } from '@/shared/types';

export interface ReferralsUiState {
  search: string;
  statusFilter: ReferralSourceStatus | 'all';
}

export interface ReferralFilterChip {
  value: ReferralSourceStatus | 'all';
  label: string;
}
