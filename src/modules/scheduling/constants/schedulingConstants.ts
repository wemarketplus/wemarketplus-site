import type { SchedulingUiState } from '../types/schedulingTypes';

export const SCHEDULING_TAGS = {
  Territories: 'Scheduling.Territories',
} as const;

// View toggle shown in the page header.
export const SCHEDULING_VIEWS: ReadonlyArray<{
  value: SchedulingUiState['view'];
  label: string;
}> = [
  { value: 'territories', label: 'Territory table' },
  { value: 'heatmap', label: 'Heat map' },
];
