// Backend CommunityLink tour status — mirrors wemarketplus-backend TourStatus.
export const CL_TOUR_STATUS = {
  Scheduled: 'scheduled',
  Completed: 'completed',
  Cancelled: 'cancelled',
  NoShow: 'no_show',
} as const;

export type ClTourStatus = (typeof CL_TOUR_STATUS)[keyof typeof CL_TOUR_STATUS];

// Select options for the Book-tour form.
export const CL_TOUR_STATUS_OPTIONS: ReadonlyArray<{
  value: ClTourStatus;
  label: string;
}> = [
  { value: CL_TOUR_STATUS.Scheduled, label: 'Scheduled' },
  { value: CL_TOUR_STATUS.Completed, label: 'Completed' },
  { value: CL_TOUR_STATUS.Cancelled, label: 'Cancelled' },
  { value: CL_TOUR_STATUS.NoShow, label: 'No show' },
];
