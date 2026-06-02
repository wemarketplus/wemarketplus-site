import type { ProspectStatus } from '@/shared/types';

export interface PipelineColumnConfig {
  status: ProspectStatus;
  label: string;
  tone: string;
}

export interface PipelineUiState {
  groupBy: 'status' | 'urgency';
}
