// Types for the self-contained CommunityLink Gold CRM demo. Mirrors the data
// shapes in the live reference (communitylinkgold-demo.html). Types only — no
// runtime code (per the enforced modular architecture).

export type GoldRole =
  | 'director'
  | 'admin'
  | 'marketer'
  | 'maintenance'
  | 'housekeeping';

export type GoldTabKey =
  | 'dashboard'
  | 'occupancy'
  | 'leads'
  | 'tours'
  | 'refs'
  | 'apartments'
  | 'makeready'
  | 'maintenance'
  | 'housekeeping'
  | 'tasks'
  | 'reports'
  | 'settings';

export type Urgency = 'High' | 'Medium' | 'Low' | '';

export type LeadStatus =
  | 'Inquiry'
  | 'Follow-up'
  | 'Tour Scheduled'
  | 'Proposal Sent'
  | 'Decision Pending'
  | 'Move-In';

export type AptStatus =
  | 'occupied'
  | 'available'
  | 'make_ready'
  | 'on_notice'
  | 'reserved'
  | 'maintenance';

export type MaintPriority = 'urgent' | 'High' | 'Med' | 'Low';
export type MaintStatus = 'open' | 'in_progress' | 'scheduled' | 'completed';
export type HkStatus = 'not_started' | 'in_progress' | 'scheduled' | 'completed';
export type TaskPriority = 'High' | 'Med' | 'Low';
export type TourStatus = 'Confirmed' | 'Pending';

export interface Lead {
  id: number;
  name: string;
  care: string;
  status: LeadStatus;
  urgency: Urgency;
  source: string;
  phone: string;
  fu: string;
  notes: string;
}

export interface Apartment {
  id: number;
  unit: string;
  type: string;
  care: string;
  sqft: number;
  status: AptStatus;
  resident: string;
  rate: number;
  mrTasks: number;
}

export interface MrTicket {
  id: number;
  unit: string;
  type: string;
  moveout: string;
  target: string;
  pct: number;
  // Each entry is a task label; a leading "done:" marks it complete (mirrors
  // the reference's in-string toggle encoding).
  tasks: string[];
  assignee: string;
}

export interface MaintTicket {
  id: number;
  ticket: string;
  unit: string;
  resident: string;
  issue: string;
  priority: MaintPriority;
  status: MaintStatus;
  assignee: string;
  created: string;
}

export interface HkTask {
  id: number;
  task: string;
  unit: string;
  type: string;
  status: HkStatus;
  assignee: string;
  due: string;
}

export interface Referral {
  id: number;
  name: string;
  type: string;
  org: string;
  leads: number;
  last: string;
}

export interface Task {
  id: number;
  title: string;
  due: string;
  priority: TaskPriority;
  done: boolean;
}

export interface Tour {
  name: string;
  care: string;
  date: string;
  time: string;
  guide: string;
  status: TourStatus;
}

export interface NavItem {
  k: GoldTabKey;
  l: string;
}

export interface NavSection {
  sec: string;
  items: NavItem[];
}

// Input shapes for the create reducers (id is assigned by the slice).
export type NewLeadInput = Pick<Lead, 'name' | 'care'>;
export type NewReferralInput = Pick<Referral, 'name' | 'org'>;
export type NewApartmentInput = Pick<Apartment, 'unit' | 'type' | 'care'>;
export type NewMrTicketInput = Pick<MrTicket, 'unit' | 'target'>;
export type NewMaintInput = Pick<MaintTicket, 'unit' | 'issue'>;
export type NewHkInput = Pick<HkTask, 'task' | 'unit'>;
export type NewTaskInput = Pick<Task, 'title' | 'due' | 'priority'>;
