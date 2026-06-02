// Seed data for the CommunityLink Pro CRM demo — copied verbatim from the
// live reference (communitylinkpro-demo.html). Static values only.
import type {
  Lead,
  MileageEntry,
  Note,
  OutreachEntry,
  Referral,
  Task,
  Tour,
} from '../types/clDemoTypes';

export const SEED_LEADS: readonly Lead[] = [
  { id: 1, name: 'Dorothy Harrison', age: 82, care: 'Independent Living', status: 'Tour Scheduled', source: 'Physician Referral', urgency: 'Hot', phone: '(214) 555-0142', notes: 'Family meeting needed. Son James is POA.', fu: '2026-02-14' },
  { id: 2, name: 'Walter Simmons', age: 78, care: 'Assisted Living', status: 'Inquiry', source: 'Website', urgency: 'Warm', phone: '(972) 555-0278', notes: 'Looking for 2BR. Wife passed last month.', fu: '2026-02-16' },
  { id: 3, name: 'Gloria Tran', age: 86, care: 'Memory Care', status: 'Proposal Sent', source: 'Hospital Discharge', urgency: 'Hot', phone: '(469) 555-0391', notes: 'MNSD diagnosis. Daughter wants quick move-in.', fu: '2026-02-13' },
  { id: 4, name: 'Raymond Flores', age: 74, care: 'Independent Living', status: 'Follow-up', source: 'Community Event', urgency: 'Cold', phone: '(817) 555-0456', notes: 'Not ready yet. Call back in March.', fu: '2026-03-05' },
  { id: 5, name: 'Edna Michaels', age: 80, care: 'Assisted Living', status: 'Tour Scheduled', source: 'Google', urgency: 'Warm', phone: '(214) 555-0567', notes: 'Has VA benefits. Confirm eligibility.', fu: '2026-02-15' },
  { id: 6, name: 'James Owens', age: 88, care: 'Memory Care', status: 'Move-In', source: 'Physician Referral', urgency: '', phone: '(972) 555-0678', notes: 'Moved in Jan 28. Very smooth transition.', fu: '' },
  { id: 7, name: 'Ruth Patterson', age: 76, care: 'Independent Living', status: 'Inquiry', source: 'Word of Mouth', urgency: 'Warm', phone: '(214) 555-0789', notes: 'Daughter called. Mom is on waiting list elsewhere.', fu: '2026-02-20' },
];

export const SEED_REFERRALS: readonly Referral[] = [
  { id: 1, name: 'Dr. Amanda Chen', type: 'Physician', org: 'Dallas Medical Group', phone: '(214) 555-1001', leads: 8, last: '2026-02-10' },
  { id: 2, name: 'Sarah Kim RN', type: 'Hospital', org: 'Parkland Hospital', phone: '(214) 555-1002', leads: 5, last: '2026-02-08' },
  { id: 3, name: 'Tom Walsh SW', type: 'Social Worker', org: 'Methodist Senior Care', phone: '(972) 555-1003', leads: 3, last: '2026-01-30' },
  { id: 4, name: 'Riverside Rehab', type: 'Rehab / SNF', org: 'Riverside PT & Rehab', phone: '(469) 555-1004', leads: 6, last: '2026-02-11' },
  { id: 5, name: 'Grace Liu', type: 'Community', org: 'Senior Activity Center', phone: '(817) 555-1005', leads: 2, last: '2026-01-25' },
];

export const SEED_TASKS: readonly Task[] = [
  { id: 1, title: 'Call Dorothy Harrison — tour confirmation', due: '2026-02-13', priority: 'High', done: false, assignee: 'Sarah M.' },
  { id: 2, title: 'Send Gloria Tran proposal follow-up', due: '2026-02-13', priority: 'High', done: false, assignee: 'Sarah M.' },
  { id: 3, title: 'Submit mileage for week of Feb 10', due: '2026-02-14', priority: 'Med', done: false, assignee: 'James K.' },
  { id: 4, title: 'Schedule Edna Michaels tour', due: '2026-02-15', priority: 'High', done: false, assignee: 'Maria L.' },
  { id: 5, title: 'Riverside Rehab thank-you gift drop-off', due: '2026-02-12', priority: 'Low', done: true, assignee: 'James K.' },
];

export const SEED_TOURS: readonly Tour[] = [
  { id: 1, name: 'Dorothy Harrison', care: 'IL', date: '2026-02-14', time: '10:00 AM', guide: 'Sarah M.', status: 'Confirmed' },
  { id: 2, name: 'Edna Michaels', care: 'AL', date: '2026-02-15', time: '2:00 PM', guide: 'Sarah M.', status: 'Confirmed' },
  { id: 3, name: 'Ruth Patterson', care: 'IL', date: '2026-02-17', time: '11:00 AM', guide: 'TBD', status: 'Pending' },
];

export const SEED_OUTREACH: readonly OutreachEntry[] = [
  { id: 1, date: '2026-02-11', location: 'Parkland Hospital', contact: 'Sarah Kim RN', type: 'Hospital Visit', miles: 12, notes: 'Left brochures. Follow-up needed.' },
  { id: 2, date: '2026-02-10', location: 'Dallas Medical Group', contact: 'Dr. Amanda Chen', type: 'Physician Visit', miles: 8, notes: 'Discussed 2 potential patients.' },
  { id: 3, date: '2026-02-09', location: 'Riverside PT', contact: 'Tom Walsh', type: 'Referral Visit', miles: 15, notes: 'Lunch meeting. Building relationship.' },
  { id: 4, date: '2026-02-07', location: 'Senior Activity Center', contact: 'Events Coordinator', type: 'Community Event', miles: 6, notes: 'Distributed flyers. 3 follow-up inquiries.' },
];

export const SEED_MILEAGE: readonly MileageEntry[] = [
  { id: 1, date: '2026-02-11', from: 'Sunrise Senior Living', to: 'Parkland Hospital', miles: 12, purpose: 'Hospital Outreach' },
  { id: 2, date: '2026-02-10', from: 'Sunrise Senior Living', to: 'Dallas Medical Group', miles: 8, purpose: 'Physician Visit' },
  { id: 3, date: '2026-02-09', from: 'Sunrise Senior Living', to: 'Riverside PT', miles: 15, purpose: 'Referral Lunch' },
  { id: 4, date: '2026-02-07', from: 'Sunrise Senior Living', to: 'Senior Activity Center', miles: 6, purpose: 'Community Event' },
];

export const SEED_NOTES: readonly Note[] = [
  { id: 1, leadId: 1, contact: 'Phone Call', summary: 'Spoke with son James. Dorothy recovering from hip replacement. Very warm.', next: 'Tour confirmation call Feb 13', date: '2026-02-11' },
  { id: 2, leadId: 3, contact: 'Family Meeting', summary: 'Met with daughter Lisa and son Kevin. Memory care diagnosis confirmed.', next: 'HOT — decision expected this week', date: '2026-02-10' },
];

// nextId starts at 100 in the reference so new entities never collide with seeds.
export const SEED_NEXT_ID = 100;

// Form option lists (static — used by the add/edit forms).
export const CARE_LEVELS = ['Independent Living', 'Assisted Living', 'Memory Care', 'Undecided'] as const;
export const LEAD_STATUSES = ['Inquiry', 'Tour Scheduled', 'Proposal Sent', 'Follow-up', 'Decision Pending', 'Move-In'] as const;
export const LEAD_STATUSES_FULL = ['Inquiry', 'Follow-up', 'Tour Scheduled', 'Proposal Sent', 'Decision Pending', 'Move-In', 'Lost'] as const;
export const URGENCIES = ['Warm', 'Hot', 'Cold'] as const;
export const LEAD_SOURCES = ['Website', 'Physician Referral', 'Hospital Discharge', 'Social Worker', 'Community Event', 'Word of Mouth', 'Google / Online'] as const;
export const REFERRAL_TYPES = ['Physician', 'Hospital', 'Social Worker', 'Rehab / SNF', 'Home Health', 'Community Event', 'Financial Advisor'] as const;
export const TOUR_CARE_LEVELS = ['IL', 'AL', 'MC'] as const;
export const TOUR_TYPES = ['In-Person', 'Virtual', 'Phone'] as const;
export const GPS_VISIT_TYPES = ['Hospital Visit', 'Physician Visit', 'Social Worker Visit', 'Rehab / SNF Visit', 'Community Event', 'Lunch & Learn'] as const;
export const NOTE_CONTACT_TYPES = ['Phone Call', 'In-Person Visit', 'Email', 'Text / SMS', 'Tour', 'Family Meeting'] as const;

export const AI_QUICK_PROMPTS = [
  'Give me a tour follow-up script for a warm IL prospect',
  'How do I handle: "We need more time to decide"?',
  'Write a re-engagement email for a cold lead',
  '5 talking points for a physician lunch-and-learn',
  'What questions to ask on an initial inquiry call?',
  'Help me write a thank-you note after a tour',
] as const;

export const AI_GREETING =
  "Hi! I'm your CommunityLink AI Sales Assistant. Ask me anything about senior living sales, objection handling, tour scripts, or referral strategies.";

export const AI_SYSTEM_PROMPT =
  'You are an AI sales assistant for CommunityLink CRM, a senior living sales platform. Help sales directors and marketers at independent living, assisted living, and memory care communities. Be specific, practical, and concise. Focus on: tour follow-ups, family dynamics, objection handling, referral relationship building, and occupancy goals.';

export const COMMUNITY_DEFAULTS = {
  name: 'Sunrise Senior Living',
  phone: '(214) 555-0100',
  city: 'Dallas',
  state: 'TX',
  address: '1234 Oak Drive, Dallas TX 75201',
} as const;
