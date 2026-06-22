// Clinical status enums — mirror backend BedUnitStatus / TelehealthStatus.
export const BED_UNIT_STATUS = {
  Available: 'available',
  Occupied: 'occupied',
  Reserved: 'reserved',
  Maintenance: 'maintenance',
  Discharged: 'discharged',
} as const;
export type BedUnitStatus = (typeof BED_UNIT_STATUS)[keyof typeof BED_UNIT_STATUS];

export const TELEHEALTH_STATUS = {
  Scheduled: 'scheduled',
  Completed: 'completed',
  Cancelled: 'cancelled',
  NoShow: 'no_show',
} as const;
export type TelehealthStatus = (typeof TELEHEALTH_STATUS)[keyof typeof TELEHEALTH_STATUS];
