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

export interface AiMessage {
  role: 'user' | 'assistant';
  content: string;
}

// A chat bubble rendered in the AI Assistant tab — an AiMessage plus transient
// UI flags for the "Thinking…" placeholder and the keyless "AI unavailable" reply.
export interface ChatBubble extends AiMessage {
  thinking?: boolean;
  unavailable?: boolean;
}

// Reports tab — leads-by-source bar chart rows (normalized so the largest = 100%).
export interface SourceChartRow {
  source: string;
  count: number;
  pct: number;
}

// Reports tab — pipeline snapshot table rows (% of all leads in each stage).
export interface PipelineSnapshotRow {
  stage: LeadStatus;
  count: number;
  pct: number;
}

// BadgeTone + ToastState now live in the shared demo design system; re-exported
// here so existing module imports (`from '../types/clDemoTypes'`) keep working.
export type { BadgeTone, ToastState } from '@/shared/cl-demo';

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
