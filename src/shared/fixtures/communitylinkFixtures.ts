// Design fixtures for CommunityLink (senior-living) screens. See the
// hospicelinkFixtures.ts header for the philosophy — strictly readonly
// seed data, replaced module-by-module as real endpoints land.

import {
  ApartmentStatus,
  CareLevel,
  LeadStatus,
  TicketPriority,
  TicketStatus,
  Urgency,
  type Apartment,
  type GPSCheckIn,
  type Lead,
  type MakeReadyTicket,
  type MileageEntry,
  type ServiceTicket,
  type Tour,
} from '@/shared/types';

export const LEADS_FIXTURE: readonly Lead[] = [
  {
    id: 'l-001',
    name: 'Helen Vasquez',
    careType: CareLevel.AL,
    status: LeadStatus.TourScheduled,
    urgency: Urgency.Hot,
    source: 'Family referral',
    followUpDate: '2026-05-26T17:00:00Z',
    phone: '(415) 555-0410',
    email: 'helen.v@vfamily.com',
  },
  {
    id: 'l-002',
    name: 'Roger Pierce',
    careType: CareLevel.MC,
    status: LeadStatus.Proposal,
    urgency: Urgency.Warm,
    source: 'Web inquiry',
    followUpDate: '2026-05-27T18:30:00Z',
    phone: '(415) 555-0421',
    email: 'roger@piercehome.com',
  },
  {
    id: 'l-003',
    name: 'Lillian Tran',
    careType: CareLevel.IL,
    status: LeadStatus.Inquiry,
    urgency: Urgency.Warm,
    source: 'Hospital discharge',
    followUpDate: '2026-05-25T16:00:00Z',
    phone: '(415) 555-0454',
    email: 'lillian.tran@tranfamily.org',
  },
  {
    id: 'l-004',
    name: 'Jorge Salazar',
    careType: CareLevel.AL,
    status: LeadStatus.FollowUp,
    urgency: Urgency.Cold,
    source: 'Walk-in',
    followUpDate: '2026-06-02T17:00:00Z',
    phone: '(415) 555-0469',
    email: 'jorge.s@salazarfamily.us',
  },
  {
    id: 'l-005',
    name: 'Wanda McKinley',
    careType: CareLevel.IL,
    status: LeadStatus.MoveIn,
    urgency: Urgency.Cold,
    source: 'Online ad',
    followUpDate: '2026-06-15T17:00:00Z',
    phone: '(415) 555-0473',
    email: 'wanda@mckinley.org',
  },
];

export const APARTMENTS_FIXTURE: readonly Apartment[] = [
  {
    id: 'a-201',
    unitNumber: '201',
    unitType: '1BR/1BA',
    careLevel: CareLevel.IL,
    status: ApartmentStatus.Occupied,
    residentName: 'Edna Park',
    monthlyRate: 4200,
    openMakeReadyTasks: 0,
  },
  {
    id: 'a-202',
    unitNumber: '202',
    unitType: 'Studio',
    careLevel: CareLevel.AL,
    status: ApartmentStatus.MakeReady,
    monthlyRate: 5100,
    openMakeReadyTasks: 3,
  },
  {
    id: 'a-204',
    unitNumber: '204',
    unitType: '2BR/2BA',
    careLevel: CareLevel.IL,
    status: ApartmentStatus.Reserved,
    residentName: 'Reserved — Vasquez',
    monthlyRate: 5450,
    openMakeReadyTasks: 0,
  },
  {
    id: 'a-301',
    unitNumber: '301',
    unitType: '1BR/1BA',
    careLevel: CareLevel.MC,
    status: ApartmentStatus.OnNotice,
    residentName: 'Harold Reems',
    monthlyRate: 6800,
    openMakeReadyTasks: 0,
  },
  {
    id: 'a-302',
    unitNumber: '302',
    unitType: 'Studio',
    careLevel: CareLevel.MC,
    status: ApartmentStatus.Available,
    monthlyRate: 6200,
    openMakeReadyTasks: 0,
  },
  {
    id: 'a-401',
    unitNumber: '401',
    unitType: '2BR/1BA',
    careLevel: CareLevel.AL,
    status: ApartmentStatus.Maintenance,
    monthlyRate: 5400,
    openMakeReadyTasks: 1,
  },
];

export const MAKE_READY_FIXTURE: readonly MakeReadyTicket[] = [
  {
    id: 'mr-202',
    unitNumber: '202',
    unitType: 'Studio',
    moveOutDate: '2026-05-12T00:00:00Z',
    targetDate: '2026-05-27T00:00:00Z',
    pctComplete: 0.62,
    assignedTo: 'Marisol Quinto',
  },
  {
    id: 'mr-301',
    unitNumber: '301',
    unitType: '1BR/1BA',
    moveOutDate: '2026-05-30T00:00:00Z',
    targetDate: '2026-06-12T00:00:00Z',
    pctComplete: 0.05,
    assignedTo: 'Jules Park',
  },
  {
    id: 'mr-401',
    unitNumber: '401',
    unitType: '2BR/1BA',
    moveOutDate: '2026-05-05T00:00:00Z',
    targetDate: '2026-05-22T00:00:00Z',
    pctComplete: 0.85,
    assignedTo: 'Marisol Quinto',
  },
];

export const MAINTENANCE_FIXTURE: readonly ServiceTicket[] = [
  {
    id: 'mt-001',
    unitNumber: '202',
    title: 'Replace HVAC filter, deep clean',
    priority: TicketPriority.Medium,
    status: TicketStatus.InProgress,
    assignedTo: 'Marisol Quinto',
  },
  {
    id: 'mt-002',
    unitNumber: '401',
    title: 'Leaky bathroom faucet',
    priority: TicketPriority.High,
    status: TicketStatus.Open,
    assignedTo: 'Jules Park',
  },
  {
    id: 'mt-003',
    unitNumber: '120',
    title: 'Smoke detector battery',
    priority: TicketPriority.Low,
    status: TicketStatus.Completed,
    assignedTo: 'Jules Park',
  },
];

export const HOUSEKEEPING_FIXTURE: readonly ServiceTicket[] = [
  {
    id: 'hk-001',
    unitNumber: '301',
    title: 'Move-out deep clean',
    priority: TicketPriority.High,
    status: TicketStatus.Open,
    assignedTo: 'Marisol Quinto',
  },
  {
    id: 'hk-002',
    unitNumber: '108',
    title: 'Weekly common area refresh',
    priority: TicketPriority.Medium,
    status: TicketStatus.InProgress,
    assignedTo: 'Daria Voss',
  },
];

export const TOURS_FIXTURE: readonly Tour[] = [
  {
    id: 'tr-001',
    prospectName: 'Helen Vasquez',
    tourDate: '2026-05-26T00:00:00Z',
    tourTime: '10:00',
    tourType: 'in_person',
    notes: 'Adult daughter will attend.',
  },
  {
    id: 'tr-002',
    prospectName: 'Roger Pierce',
    tourDate: '2026-05-27T00:00:00Z',
    tourTime: '14:30',
    tourType: 'virtual',
  },
  {
    id: 'tr-003',
    prospectName: 'Lillian Tran',
    tourDate: '2026-05-28T00:00:00Z',
    tourTime: '11:00',
    tourType: 'in_person',
    notes: 'Translator requested (Vietnamese).',
  },
];

export const GPS_CHECKINS_FIXTURE: readonly GPSCheckIn[] = [
  {
    id: 'g-001',
    organization: 'St. Joseph SNF',
    contactName: 'Liam Foster',
    gpsLocation: '37.7610,-122.4630',
    visitType: 'Drop-in',
    visitDate: '2026-05-23T20:00:00Z',
  },
  {
    id: 'g-002',
    organization: 'Mercy Hospital',
    contactName: 'Rebecca Holm',
    gpsLocation: '37.7838,-122.4090',
    visitType: 'Scheduled meeting',
    visitDate: '2026-05-24T18:00:00Z',
  },
];

export const MILEAGE_FIXTURE: readonly MileageEntry[] = [
  {
    id: 'mi-001',
    distanceMiles: 12.4,
    date: '2026-05-23T20:00:00Z',
    purpose: 'Visit St. Joseph SNF',
  },
  {
    id: 'mi-002',
    distanceMiles: 8.1,
    date: '2026-05-24T18:00:00Z',
    purpose: 'Mercy Hospital scheduled meeting',
  },
  {
    id: 'mi-003',
    distanceMiles: 4.6,
    date: '2026-05-24T22:00:00Z',
    purpose: 'Lunch drop-off at Bayview Internal',
  },
];
