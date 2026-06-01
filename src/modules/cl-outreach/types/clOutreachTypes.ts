import type { GPSCheckIn, MileageEntry } from '@/shared/types';

export type { GPSCheckIn, MileageEntry };

export interface ClOutreachUiState {
  view: 'checkin' | 'mileage' | 'log';
}
