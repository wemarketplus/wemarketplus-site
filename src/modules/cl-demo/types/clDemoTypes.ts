// Types for the self-contained CommunityLink Pro CRM demo. Mirrors the data
// shapes in the live reference (communitylinkpro-demo.html). Types only — no
// runtime code (per the enforced modular architecture).

export type DemoRole = 'admin' | 'marketer';

export type TabKey =
  | 'dashboard'
  | 'addlead'
  | 'leads'
  | 'refs'
  | 'addref'
  | 'tours'
  | 'gps'
  | 'mileage'
  | 'outreach'
  | 'tasks'
  | 'notes'
  | 'ai'
  | 'reports'
  | 'settings';

export type Urgency = 'Hot' | 'Warm' | 'Cold' | '';

export type LeadStatus =
  | 'Inquiry'
  | 'Follow-up'
  | 'Tour Scheduled'
  | 'Proposal Sent'
  | 'Decision Pending'
  | 'Move-In'
  | 'Lost';

export type TaskPriority = 'High' | 'Med' | 'Low';

export type TourStatus = 'Confirmed' | 'Pending';

export interface Lead {
  id: number;
  name: string;
  age?: number | string;
  care: string;
  status: LeadStatus;
  source: string;
  urgency: Urgency;
  phone: string;
  notes: string;
  fu: string;
}

export interface Referral {
  id: number;
  name: string;
  type: string;
  org: string;
  phone: string;
  leads: number;
  last: string;
}

export interface Task {
  id: number;
  title: string;
  due: string;
  priority: TaskPriority;
  done: boolean;
  assignee: string;
}

export interface Tour {
  id: number;
  name: string;
  care: string;
  date: string;
  time: string;
  guide: string;
  status: TourStatus;
}

export interface OutreachEntry {
  id: number;
  date: string;
  location: string;
  contact: string;
  type: string;
  miles: number;
  notes: string;
}

export interface MileageEntry {
  id: number;
  date: string;
  from: string;
  to: string;
  miles: number;
  purpose: string;
}

export interface Note {
  id: number;
  leadId: number | null;
  contact: string;
  summary: string;
  next: string;
  date: string;
}

export interface NavItem {
  k: TabKey;
  l: string;
}

export interface NavSection {
  sec: string;
  items: NavItem[];
}

export interface ToastState {
  message: string;
  error: boolean;
  // Bumped on every toast so the autohide effect re-runs even for an
  // identical message (mirrors the reference's re-triggerable T()).
  nonce: number;
}

export interface AiMessage {
  role: 'user' | 'assistant';
  content: string;
}

// Badge tone keys — mirror the reference's .bg/.ba/.bb/.br/.bx classes.
export type BadgeTone = 'green' | 'amber' | 'blue' | 'red' | 'neutral';

// Input shapes for the create reducers (id is assigned by the slice).
export type NewLeadInput = Omit<Lead, 'id'>;
export type NewReferralInput = Pick<
  Referral,
  'name' | 'type' | 'org' | 'phone'
>;
export type NewTaskInput = Pick<
  Task,
  'title' | 'due' | 'priority' | 'assignee'
>;
export type NewTourInput = Pick<
  Tour,
  'name' | 'care' | 'date' | 'time' | 'guide'
>;
export type NewNoteInput = Pick<
  Note,
  'leadId' | 'contact' | 'summary' | 'next'
> & { date: string };
export type NewMileageInput = Pick<
  MileageEntry,
  'date' | 'from' | 'to' | 'miles' | 'purpose'
>;
export type NewOutreachInput = Pick<
  OutreachEntry,
  'date' | 'location' | 'contact' | 'type' | 'miles' | 'notes'
>;

// Edited fields saved from the lead detail modal.
export type LeadEdit = Pick<
  Lead,
  'status' | 'urgency' | 'fu' | 'source' | 'notes'
> & { id: number };
