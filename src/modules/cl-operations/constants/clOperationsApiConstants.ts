// Backend CommunityLink property-operations enums — mirror wemarketplus-backend
// communitylink.constants (ApartmentStatus, MakeReady*, Maintenance*, etc.).
export const CL_CARE_LEVEL = {
  IndependentLiving: 'IL',
  AssistedLiving: 'AL',
  MemoryCare: 'MC',
} as const;
export type ClCareLevel = (typeof CL_CARE_LEVEL)[keyof typeof CL_CARE_LEVEL];

export const APARTMENT_STATUS = {
  Available: 'available',
  Occupied: 'occupied',
  Reserved: 'reserved',
  /**
   * Spoken for by a waiting list — interest queued, nothing signed. Distinct from
   * Reserved (a signed resident), which is why only Reserved counts toward
   * occupancy server-side.
   */
  Waitlisted: 'waitlisted',
  OnNotice: 'on_notice',
  MakeReady: 'make_ready',
  Maintenance: 'maintenance',
  Offline: 'offline',
} as const;
export type ApartmentStatus = (typeof APARTMENT_STATUS)[keyof typeof APARTMENT_STATUS];

export const MAKE_READY_STATUS = {
  Pending: 'pending',
  InProgress: 'in_progress',
  Completed: 'completed',
  Blocked: 'blocked',
} as const;
export type MakeReadyStatus = (typeof MAKE_READY_STATUS)[keyof typeof MAKE_READY_STATUS];

export const MAKE_READY_CATEGORY = {
  Maintenance: 'maintenance',
  Housekeeping: 'housekeeping',
  Inspection: 'inspection',
  General: 'general',
} as const;
export type MakeReadyCategory = (typeof MAKE_READY_CATEGORY)[keyof typeof MAKE_READY_CATEGORY];

export const MAINTENANCE_STATUS = {
  Open: 'open',
  InProgress: 'in_progress',
  Scheduled: 'scheduled',
  Completed: 'completed',
  Cancelled: 'cancelled',
} as const;
export type MaintenanceStatus = (typeof MAINTENANCE_STATUS)[keyof typeof MAINTENANCE_STATUS];

export const TICKET_PRIORITY = {
  Urgent: 'urgent',
  High: 'high',
  Medium: 'medium',
  Low: 'low',
} as const;
export type TicketPriority = (typeof TICKET_PRIORITY)[keyof typeof TICKET_PRIORITY];

export const HOUSEKEEPING_STATUS = {
  Pending: 'pending',
  InProgress: 'in_progress',
  Completed: 'completed',
  Skipped: 'skipped',
} as const;
export type HousekeepingStatus = (typeof HOUSEKEEPING_STATUS)[keyof typeof HOUSEKEEPING_STATUS];
