import type { ClOutreachUiState } from '../types/clOutreachTypes';

export const OUTREACH_VIEWS: ReadonlyArray<{
  value: ClOutreachUiState['view'];
  label: string;
}> = [
  { value: 'checkin', label: 'GPS check-in' },
  { value: 'mileage', label: 'Mileage' },
  { value: 'log', label: 'Outreach log' },
];
