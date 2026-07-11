import type { PillProps } from '@/shared/ui/data-display';
import type { EntitySelectOption } from '@/shared/ui/entity';
import { CL_TOUR_STATUS, type ClTourStatus } from './clToursApiConstants';

export const CL_TOURS_PAGE_SIZE = 20;

export const TOUR_STATUS_LABELS: Record<ClTourStatus, string> = {
  [CL_TOUR_STATUS.Scheduled]: 'Scheduled',
  [CL_TOUR_STATUS.Completed]: 'Completed',
  [CL_TOUR_STATUS.Cancelled]: 'Cancelled',
  [CL_TOUR_STATUS.NoShow]: 'No show',
};

export const TOUR_STATUS_PILL: Record<ClTourStatus, PillProps['tone']> = {
  [CL_TOUR_STATUS.Scheduled]: 'b',
  [CL_TOUR_STATUS.Completed]: 'g',
  [CL_TOUR_STATUS.Cancelled]: 'r',
  [CL_TOUR_STATUS.NoShow]: 'y',
};

export const TOUR_STATUS_OPTIONS: readonly EntitySelectOption[] = Object.entries(
  TOUR_STATUS_LABELS,
).map(([value, label]) => ({ value, label }));

export const TOUR_DURATION_OPTIONS: readonly EntitySelectOption[] = [
  { value: '30', label: '30 min' },
  { value: '45', label: '45 min' },
  { value: '60', label: '60 min' },
  { value: '90', label: '90 min' },
];
