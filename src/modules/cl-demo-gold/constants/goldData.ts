// Seed data for the CommunityLink Gold CRM demo — verbatim from the reference
// (communitylinkgold-demo.html LEADS/APTS/MR_TICKETS/MAINT_TICKETS/HK_TASKS/
// REFERRALS/TASKS/TOURS). Static values only (per the modular architecture).
import type {
  Apartment,
  HkTask,
  Lead,
  LeadStatus,
  MaintTicket,
  MrTicket,
  Referral,
  Task,
  Tour,
} from '../types/goldTypes';

export const SEED_LEADS: Lead[] = [
  { id: 1, name: 'Dorothy Harrison', care: 'Independent Living', status: 'Tour Scheduled', urgency: 'Hot', source: 'Physician', phone: '(214)555-0142', fu: '2026-02-14', notes: 'Son James is POA.' },
  { id: 2, name: 'Walter Simmons', care: 'Assisted Living', status: 'Inquiry', urgency: 'Warm', source: 'Website', phone: '(972)555-0278', fu: '2026-02-16', notes: 'Looking for 2BR.' },
  { id: 3, name: 'Gloria Tran', care: 'Memory Care', status: 'Proposal Sent', urgency: 'Hot', source: 'Hospital Discharge', phone: '(469)555-0391', fu: '2026-02-13', notes: 'MNSD diagnosis. Quick move wanted.' },
  { id: 4, name: 'Raymond Flores', care: 'Independent Living', status: 'Follow-up', urgency: 'Cold', source: 'Community Event', phone: '(817)555-0456', fu: '2026-03-05', notes: 'Not ready yet.' },
  { id: 5, name: 'Edna Michaels', care: 'Assisted Living', status: 'Tour Scheduled', urgency: 'Warm', source: 'Google', phone: '(214)555-0567', fu: '2026-02-15', notes: 'Has VA benefits.' },
  { id: 6, name: 'James Owens', care: 'Memory Care', status: 'Move-In', urgency: '', source: 'Physician', phone: '(972)555-0678', fu: '', notes: 'Moved in Jan 28.' },
];

export const SEED_APTS: Apartment[] = [
  { id: 1, unit: '101', type: '1BR/1BA', care: 'IL', sqft: 620, status: 'occupied', resident: 'Vera Holmes', rate: 3400, mrTasks: 0 },
  { id: 2, unit: '102', type: '2BR/2BA', care: 'IL', sqft: 890, status: 'available', resident: '', rate: 3800, mrTasks: 0 },
  { id: 3, unit: '103', type: 'Studio', care: 'AL', sqft: 420, status: 'make_ready', resident: '', rate: 4200, mrTasks: 4 },
  { id: 4, unit: '104', type: '1BR/1BA', care: 'MC', sqft: 540, status: 'on_notice', resident: 'Earl Davis', rate: 5600, mrTasks: 0 },
  { id: 5, unit: '105', type: '2BR/2BA', care: 'IL', sqft: 910, status: 'occupied', resident: 'Ruth & Harold Kim', rate: 3900, mrTasks: 0 },
  { id: 6, unit: '106', type: 'Studio', care: 'AL', sqft: 400, status: 'reserved', resident: 'Martha Jones (incoming)', rate: 4100, mrTasks: 0 },
  { id: 7, unit: '107', type: '1BR/1BA', care: 'IL', sqft: 650, status: 'occupied', resident: 'Frank Torres', rate: 3500, mrTasks: 0 },
  { id: 8, unit: '108', type: '2BR/2BA', care: 'MC', sqft: 870, status: 'make_ready', resident: '', rate: 5800, mrTasks: 3 },
];

export const SEED_MR_TICKETS: MrTicket[] = [
  { id: 1, unit: '103', type: 'Studio', moveout: '2026-01-30', target: '2026-02-15', pct: 60, tasks: ['Trash out', 'Locks changed', 'Paint in progress', 'Carpet scheduled', 'HVAC check', 'Final clean'], assignee: 'Carlos R.' },
  { id: 2, unit: '108', type: '2BR/2BA', moveout: '2026-01-25', target: '2026-02-14', pct: 75, tasks: ['Trash out', 'Locks changed', 'Paint done', 'Window repair done', 'Deep clean in progress', 'Inspection'], assignee: 'Marcus T.' },
];

export const SEED_MAINT_TICKETS: MaintTicket[] = [
  { id: 1, ticket: 'M-001', unit: '101', resident: 'Vera Holmes', issue: 'Bathroom faucet dripping', priority: 'Low', status: 'open', assignee: 'Carlos R.', created: '2026-02-10' },
  { id: 2, ticket: 'M-002', unit: '105', resident: 'Ruth Kim', issue: 'Thermostat not responding', priority: 'High', status: 'in_progress', assignee: 'Marcus T.', created: '2026-02-11' },
  { id: 3, ticket: 'M-003', unit: '103', resident: '', issue: 'Paint touch-up make-ready', priority: 'Med', status: 'scheduled', assignee: 'Carlos R.', created: '2026-02-01' },
  { id: 4, ticket: 'M-004', unit: '108', resident: '', issue: 'Window repair make-ready', priority: 'High', status: 'in_progress', assignee: 'Marcus T.', created: '2026-02-05' },
  { id: 5, ticket: 'M-005', unit: '107', resident: 'Frank Torres', issue: 'Light fixture replacement', priority: 'Low', status: 'completed', assignee: 'Carlos R.', created: '2026-02-08' },
];

export const SEED_HK_TASKS: HkTask[] = [
  { id: 1, task: 'Unit 103 Make-Ready Deep Clean', unit: '103', type: 'Make-Ready', status: 'in_progress', assignee: 'Maria G.', due: '2026-02-13' },
  { id: 2, task: 'Unit 108 Make-Ready Deep Clean', unit: '108', type: 'Make-Ready', status: 'not_started', assignee: 'Lisa P.', due: '2026-02-14' },
  { id: 3, task: 'Common Areas Daily Clean', unit: 'Common', type: 'Daily', status: 'completed', assignee: 'Maria G.', due: '2026-02-12' },
  { id: 4, task: 'Dining Room Weekly Deep Clean', unit: 'Dining', type: 'Deep Clean', status: 'scheduled', assignee: 'Team', due: '2026-02-15' },
  { id: 5, task: 'Unit 102 Vacancy Clean', unit: '102', type: 'Vacancy', status: 'completed', assignee: 'Lisa P.', due: '2026-02-09' },
];

export const SEED_REFERRALS: Referral[] = [
  { id: 1, name: 'Dr. Amanda Chen', type: 'Physician', org: 'Dallas Medical Group', leads: 8, last: '2026-02-10' },
  { id: 2, name: 'Sarah Kim RN', type: 'Hospital', org: 'Parkland Hospital', leads: 5, last: '2026-02-08' },
  { id: 3, name: 'Tom Walsh SW', type: 'Social Worker', org: 'Methodist Senior Care', leads: 3, last: '2026-01-30' },
];

export const SEED_TASKS: Task[] = [
  { id: 1, title: 'Schedule Unit 104 make-ready for Mar 1', due: '2026-02-20', priority: 'High', done: false },
  { id: 2, title: 'Call Dorothy Harrison — tour confirmation', due: '2026-02-13', priority: 'High', done: false },
  { id: 3, title: 'Review Unit 103 make-ready progress', due: '2026-02-13', priority: 'Med', done: false },
  { id: 4, title: 'Submit mileage report', due: '2026-02-14', priority: 'Low', done: true },
];

// Tours are presentation-only in the reference (rTours holds a local array; the
// "Schedule Tour" form just toasts). Kept as a constant to match 1:1.
export const TOURS: Tour[] = [
  { name: 'Dorothy Harrison', care: 'IL', date: '2026-02-14', time: '10:00 AM', guide: 'Sarah M.', status: 'Confirmed' },
  { name: 'Edna Michaels', care: 'AL', date: '2026-02-15', time: '2:00 PM', guide: 'Sarah M.', status: 'Confirmed' },
  { name: 'New Inquiry', care: 'IL', date: '2026-02-17', time: '11:00 AM', guide: 'TBD', status: 'Pending' },
];

// nextId seed (reference: var nextId=200).
export const SEED_NEXT_ID = 200;

// Lead status filter options (reference rLeads() <select>).
export const LEAD_FILTER_STATUSES: LeadStatus[] = ['Inquiry', 'Tour Scheduled', 'Proposal Sent', 'Move-In'];

// Lead status cycle order (reference updateLeadStatus()).
export const LEAD_STATUS_CYCLE: LeadStatus[] = ['Inquiry', 'Follow-up', 'Tour Scheduled', 'Proposal Sent', 'Decision Pending', 'Move-In'];
