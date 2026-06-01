// Cross-module domain entities. Each *module* still owns its own typed DTOs
// in `<module>/types/`; this file holds the shared shapes that more than one
// module references (so we don't introduce module-to-module imports).
//
// Fields mirror what wemarketplus-site renders. When the backend ships real
// DTOs, hand-mirror those into each module's own `types/` file and replace
// the shared shape only if the entity stays cross-cutting.

import type { ID, ISODateString } from './commonTypes';

// --- Hospice product ---------------------------------------------------

export const ProspectStatus = {
  Inquiry: 'inquiry',
  PendingAdmission: 'pending_admission',
  Admitted: 'admitted',
  Lost: 'lost',
} as const;
export type ProspectStatus = (typeof ProspectStatus)[keyof typeof ProspectStatus];

export const Urgency = {
  Hot: 'hot',
  Warm: 'warm',
  Cold: 'cold',
} as const;
export type Urgency = (typeof Urgency)[keyof typeof Urgency];

export interface Prospect {
  id: ID;
  name: string;
  status: ProspectStatus;
  phone: string;
  email: string;
  referralSource: string;
  assignedMarketer: string;
  nextStep: string;
  followUpDate: ISODateString;
  urgency: Urgency;
  primaryConcern?: string;
  biggestObjection?: string;
  conversionRisk?: number;
  notes?: string;
  lastContactDate?: ISODateString;
}

export const ReferralSourceStatus = {
  Green: 'green',
  Building: 'building',
  Red: 'red',
} as const;
export type ReferralSourceStatus =
  (typeof ReferralSourceStatus)[keyof typeof ReferralSourceStatus];

export interface ReferralSource {
  id: ID;
  fullName: string;
  title: string;
  organization: string;
  workPhone: string;
  cellPhone?: string;
  email: string;
  sourceType: string;
  status: ReferralSourceStatus;
  trustLevel: 1 | 2 | 3 | 4 | 5;
  priorityLevel: 'A' | 'B' | 'C';
  lastContactDate: ISODateString;
  nextScheduledVisit?: ISODateString;
  nextAction?: string;
  assignedMarketer: string;
  territoryArea?: string;
  referralCount: number;
  acceptsGifts: boolean;
}

export interface Territory {
  id: ID;
  areaName: string;
  assignedMarketer: string;
  primaryAccounts: number;
  visitsCount: number;
  admissionsCount: number;
  conversionRate: number;
}

export interface ProspectNote {
  id: ID;
  prospectId: ID;
  author: string;
  position: string;
  interactionType: string;
  contactType: string;
  urgency: Urgency;
  date: ISODateString;
  decisionMaker?: string;
  summary: string;
  patientStatus?: string;
  barriers?: string;
  nextStep: string;
  assignedTo: string;
  followUpDate: ISODateString;
  gpsLocation?: string;
}

export interface Reminder {
  id: ID;
  sourceName: string;
  actionDescription: string;
  dueStatus: 'overdue' | 'today' | 'this_week';
  dueDate: ISODateString;
  marketerId: ID;
}

// --- Senior-living product --------------------------------------------

export const CareLevel = {
  IL: 'IL',
  AL: 'AL',
  MC: 'MC',
} as const;
export type CareLevel = (typeof CareLevel)[keyof typeof CareLevel];

export const ApartmentStatus = {
  Available: 'available',
  Occupied: 'occupied',
  Reserved: 'reserved',
  OnNotice: 'on_notice',
  MakeReady: 'make_ready',
  Maintenance: 'maintenance',
  Offline: 'offline',
} as const;
export type ApartmentStatus =
  (typeof ApartmentStatus)[keyof typeof ApartmentStatus];

export interface Apartment {
  id: ID;
  unitNumber: string;
  unitType: string;
  careLevel: CareLevel;
  status: ApartmentStatus;
  residentName?: string;
  monthlyRate: number;
  openMakeReadyTasks: number;
}

export const TicketPriority = {
  Urgent: 'urgent',
  High: 'high',
  Medium: 'medium',
  Low: 'low',
} as const;
export type TicketPriority = (typeof TicketPriority)[keyof typeof TicketPriority];

export const TicketStatus = {
  Open: 'open',
  InProgress: 'in_progress',
  Completed: 'completed',
} as const;
export type TicketStatus = (typeof TicketStatus)[keyof typeof TicketStatus];

export interface MakeReadyTicket {
  id: ID;
  unitNumber: string;
  unitType: string;
  moveOutDate: ISODateString;
  targetDate: ISODateString;
  pctComplete: number;
  assignedTo: string;
}

export interface ServiceTicket {
  id: ID;
  unitNumber: string;
  title: string;
  priority: TicketPriority;
  status: TicketStatus;
  assignedTo: string;
  description?: string;
}

export const LeadStatus = {
  Inquiry: 'inquiry',
  TourScheduled: 'tour_scheduled',
  Proposal: 'proposal',
  FollowUp: 'follow_up',
  MoveIn: 'move_in',
  Lost: 'lost',
} as const;
export type LeadStatus = (typeof LeadStatus)[keyof typeof LeadStatus];

export interface Lead {
  id: ID;
  name: string;
  careType: CareLevel;
  status: LeadStatus;
  urgency: Urgency;
  source: string;
  followUpDate: ISODateString;
  phone: string;
  email: string;
  notes?: string;
}

export interface Tour {
  id: ID;
  prospectName: string;
  tourDate: ISODateString;
  tourTime: string;
  tourType: 'in_person' | 'virtual' | 'phone';
  notes?: string;
}

export interface GPSCheckIn {
  id: ID;
  organization: string;
  contactName: string;
  gpsLocation: string;
  visitType: string;
  visitDate: ISODateString;
}

export interface MileageEntry {
  id: ID;
  distanceMiles: number;
  date: ISODateString;
  purpose: string;
  notes?: string;
}

// --- Shared ------------------------------------------------------------

export interface AppNotification {
  id: ID;
  category: 'system' | 'task' | 'mention' | 'alert';
  title: string;
  body: string;
  createdAt: ISODateString;
  read: boolean;
  href?: string;
}
