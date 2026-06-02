import type { Prospect, ProspectStatus, Urgency } from '@/shared/types';

export type { Prospect };

export type ProspectField = keyof Prospect;

export interface ProspectsUiState {
  search: string;
  statusFilter: ProspectStatus | 'all';
  urgencyFilter: Urgency | 'all';
}
