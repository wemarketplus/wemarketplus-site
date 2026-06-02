import type { GPSCheckIn, MileageEntry } from '@/shared/types';

export type { GPSCheckIn, MileageEntry };

export interface ClOutreachUiState {
  view: 'checkin' | 'mileage' | 'log';
}

// --- Component prop types ---

export interface CheckInListProps {
  items: readonly GPSCheckIn[];
}

export interface MileageListProps {
  entries: readonly MileageEntry[];
}
