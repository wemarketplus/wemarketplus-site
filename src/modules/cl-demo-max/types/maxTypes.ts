// Types for the self-contained CommunityLink Max CRM demo. Mirrors the data
// shapes in the live reference (communitylinkmax-demo.html). Types only — no
// runtime code (per the enforced modular architecture).

export type MaxRole =
  | 'owner'
  | 'director'
  | 'salesadmissions'
  | 'admin'
  | 'marketer'
  | 'maintenance'
  | 'housekeeping';

export type MaxTabKey =
  | 'dashboard'
  | 'occupancy'
  | 'leads'
  | 'referrals'
  | 'paidrefs'
  | 'tours'
  | 'refs'
  | 'apartments'
  | 'makeready'
  | 'maintenance'
  | 'housekeeping'
  | 'tasks'
  | 'mileage'
  | 'notes'
  | 'gift'
  | 'alertsettings'
  | 'finsettings'
  | 'reports'
  | 'settings'
  | 'ledger'
  | 'revenue'
  | 'concessions'
  | 'loc'
  | 'competitors'
  | 'aircall';

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
  | 'maintenance'
  | 'offline';
export type MaintPriority = 'Urgent' | 'urgent' | 'High' | 'Med' | 'Medium' | 'Low';
export type MaintStatus = 'open' | 'in_progress' | 'scheduled' | 'waiting_parts' | 'completed';
export type HkStatus = 'not_started' | 'in_progress' | 'scheduled' | 'completed';
export type TaskPriority = 'High' | 'Med' | 'Low';
export type TourStatus = 'Confirmed' | 'Pending';

export interface Lead {
  id: number;
  name: string;
  care: string;
  status: string;
  urgency: Urgency;
  source: string;
  phone: string;
  fu: string;
  notes: string;
  email?: string;
  budget?: string;
  assigned?: string;
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
  tasks: string[];
  assignee: string;
}

export interface MaintTicket {
  id: number;
  ticket: string;
  unit: string;
  resident: string;
  issue: string;
  priority: string;
  status: string;
  assignee: string;
  created: string;
}

export interface HkTask {
  id: number;
  task: string;
  unit: string;
  type: string;
  status: string;
  assignee: string;
  due: string;
}

export interface RefSource {
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
  priority: string;
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

export interface ActivityNote {
  id: number;
  type: 'aircall' | 'manual';
  comm_type: string;
  contact_name?: string;
  prospect_name?: string;
  summary: string;
  outcome?: string;
  next_step?: string;
  follow_up_date?: string | null;
  stage?: string;
  created_at: string;
  user_name?: string;
}

// rReferrals() paid-referral pipeline rows.
export interface PaidReferral {
  id: number;
  source: string;
  partner: string;
  type: 'Paid' | 'Organic';
  fee: number;
  feeStatus: 'Paid' | 'Pending' | 'N/A';
  name: string;
  care: string;
  stage: string;
  urgency: Urgency;
  assigned: string;
  phone: string;
  tourDate: string;
  moveInTarget: string;
  notes: string;
  lostReason: string;
  created: string;
}

// rPaidRefs() portal rows (separate data set in the reference).
export interface PaidRefPortal {
  id: string;
  prospect_name: string;
  source_name: string;
  prospect_phone: string;
  care_level: string;
  budget_range: string;
  move_in_timeframe: string;
  urgency: string;
  referral_fee: number;
  fee_status: string;
  stage: string;
  source_contact: string;
  source_notes: string;
  received_at: string;
  assigned_name: string;
}

export interface RevenueMonth {
  mo: string;
  bud: number;
  act: number;
}

export interface Concession {
  id: string;
  unit: string;
  resident: string;
  type: string;
  value: number;
  status: 'pending' | 'approved' | 'denied';
  by: string;
}

export interface Competitor {
  name: string;
  city: string;
  dist: number;
  il: string;
  al: string;
  mc: string;
  occ: string;
  notes: string;
}

export interface LeakItem {
  issue: string;
  type: string;
  amount: number;
  status: string;
}

export interface LocBase {
  IL: number;
  AL: number;
  MC: number;
  addon: number;
}

export interface MileageLog {
  id: string;
  date: string;
  from_addr: string;
  to_addr: string;
  miles: number;
  purpose: string;
  reimbursement: number;
  status: 'approved' | 'pending' | 'rejected';
  receipt: string | null;
  expense_type: string;
  expense_amt: number;
  submitted_by: string;
}

export interface GiftLog {
  id: string;
  recipient_name: string;
  facility_name: string;
  gift_type: string;
  gift_value: number;
  visit_date: string;
  compliance_ok: boolean;
  logged_by_name: string;
}

export interface AlertSetting {
  enabled: boolean;
  channel: string;
  roles: string[];
}
export interface AlertDef {
  key: string;
  label: string;
  desc: string;
}

export interface FinDef {
  key: string;
  label: string;
  hint: string;
  suffix: string;
}

export interface NavItem {
  k: MaxTabKey;
  l: string;
}
export interface NavSection {
  sec: string;
  items: NavItem[];
}

// Modal keys for the unified modal system (Max replaces prompts with forms).
export type ModalKey =
  | 'addLead'
  | 'addSource'
  | 'addUnit'
  | 'addTicket'
  | 'addMr'
  | 'addTask';

// Input shapes for the create reducers.
export type NewLeadInput = {
  name: string;
  care: string;
  status: string;
  urgency: Urgency;
  source: string;
  phone: string;
  fu: string;
  notes: string;
};
export type NewRefSourceInput = Pick<RefSource, 'name' | 'org' | 'type'>;
export type NewApartmentInput = Pick<Apartment, 'unit' | 'type' | 'care' | 'sqft' | 'status' | 'resident' | 'rate'>;
export type NewMaintInput = { unit: string; type: string; issue: string; priority: string; assignee: string; status: string };
export type NewMrInput = { unit: string; moveout: string; target: string; assignee: string; tasks: string[] };
export type NewTaskInput = { title: string; due: string; priority: string };
export type NewConcessionInput = Pick<Concession, 'unit' | 'resident' | 'type' | 'value'>;
export type NewCompetitorInput = Competitor;
export type NewMileageInput = Omit<MileageLog, 'id' | 'reimbursement' | 'status' | 'submitted_by'> & { reimbursement: number };
export type NewGiftInput = Omit<GiftLog, 'id' | 'logged_by_name'>;
export type NewPaidRefInput = { prospect_name: string; source_name: string; referral_fee: number };

// Aircall channel switcher (rAircall).
export type Channel = 'call' | 'text' | 'email';

// Comm-type metadata shape for the Notes timeline / Aircall (COMM_META values).
export interface CommMeta {
  icon: string;
  label: string;
  color: string;
  bg: string;
  border: string;
}

// Searchable contact-typeahead option in the Notes add-note form (rNotes).
export interface ContactOpt {
  id: string;
  name: string;
  type: string;
  sub: string;
  urgency?: string;
}
