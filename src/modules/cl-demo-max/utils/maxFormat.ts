// Pure formatting / derivation helpers for the Max demo. No side effects.
import type { BadgeTone } from '@/shared/cl-demo';
import { COMM_META, REF_SOURCE_CONTACTS } from '../constants/maxNotes';
import type {
  Apartment,
  Channel,
  ContactOpt,
  HkTask,
  Lead,
  MaintTicket,
  MrTicket,
  PaidRefPortal,
  Urgency,
} from '../types/maxTypes';

export function leadStatusTone(s: string): BadgeTone {
  if (s === 'Move-In') return 'green';
  if (s === 'Tour Scheduled') return 'blue';
  if (s === 'Proposal Sent') return 'amber';
  return 'neutral';
}
export function urgencyTone(u: Urgency | string): BadgeTone {
  if (u === 'Hot') return 'red';
  if (u === 'Warm') return 'amber';
  return 'blue';
}

export function mrTone(pct: number): BadgeTone {
  if (pct >= 100) return 'green';
  if (pct >= 50) return 'amber';
  return 'blue';
}
export function mrLabel(pct: number): string {
  if (pct >= 100) return 'Complete';
  if (pct >= 50) return 'In Progress';
  return 'Starting';
}
export function mrTaskDone(task: string): boolean {
  return task.startsWith('done:');
}
export function mrTaskLabel(task: string): string {
  return mrTaskDone(task) ? task.slice(5) : task;
}

export function countAptStatus(apts: readonly Apartment[], status: string): number {
  return apts.filter((a) => a.status === status).length;
}
export function occupancyRate(apts: readonly Apartment[]): number {
  return apts.length ? Math.round((countAptStatus(apts, 'occupied') / apts.length) * 100) : 0;
}
export function rentRoll(apts: readonly Apartment[]): number {
  return apts.filter((a) => a.status === 'occupied').reduce((s, a) => s + a.rate, 0);
}

export function hotLeadCount(leads: readonly Lead[]): number {
  return leads.filter((l) => l.urgency === 'Hot').length;
}
export function activeLeadCount(leads: readonly Lead[]): number {
  return leads.filter((l) => l.status !== 'Move-In').length;
}
export function hotLeads(leads: readonly Lead[]): Lead[] {
  return leads.filter((l) => l.urgency === 'Hot');
}
export function tourCount(leads: readonly Lead[]): number {
  return leads.filter((l) => l.status === 'Tour Scheduled').length;
}

export function countMaint(tickets: readonly MaintTicket[], status: string): number {
  return tickets.filter((t) => t.status === status).length;
}
export function openMaintCount(tickets: readonly MaintTicket[]): number {
  return tickets.filter((t) => t.status !== 'completed').length;
}
export function countHk(tasks: readonly HkTask[], status: string): number {
  return tasks.filter((t) => t.status === status).length;
}
export function openHkCount(tasks: readonly HkTask[]): number {
  return tasks.filter((t) => t.status !== 'completed').length;
}
export function openMrCount(tickets: readonly MrTicket[]): number {
  return tickets.filter((t) => t.pct < 100).length;
}

// Maps the reference's badge class keys (bg/ba/bb/br/bx) to shared BadgeTone.
export function toneFromCls(cls: string): BadgeTone {
  if (cls === 'bg') return 'green';
  if (cls === 'ba') return 'amber';
  if (cls === 'bb') return 'blue';
  if (cls === 'br') return 'red';
  return 'neutral';
}

// Competitor occupancy badge tone (reference renderCompRows occBadge).
export function occTone(occ: string): BadgeTone {
  const pct = parseInt(occ) || 0;
  if (pct >= 90) return 'green';
  if (pct >= 80) return 'amber';
  return 'red';
}

// Aircall activity-log row tone → badge class (reference rAircall toneCls).
export function aircallToneCls(tone: string): string {
  if (tone === 'green') return 'bg-[#4fc87a]/10 text-[#4fc87a]';
  if (tone === 'amber') return 'bg-[#f59e0b]/10 text-[#f59e0b]';
  if (tone === 'blue') return 'bg-[#3d9ee8]/10 text-[#3d9ee8]';
  return 'bg-white/[0.07] text-[#8ba4c4]';
}

// Composes the prefixed Aircall activity summary (reference composeSummary).
export function composeAircallSummary(comm: Channel, name: string, inner: string): string {
  const m = COMM_META[comm];
  return `${m.icon} [${m.label}] ${name} — ${inner}`;
}

// Builds the searchable contact-typeahead options for the Notes add-note form
// from current leads + active paid referrals + standing referral sources (rNotes).
export function buildContactOptions(leads: readonly Lead[], paidRefsPortal: readonly PaidRefPortal[]): ContactOpt[] {
  const list: ContactOpt[] = [];
  leads.forEach((l) => list.push({ id: 'lead-' + l.id, name: l.name, type: 'Lead', sub: [l.care, l.status, l.phone].filter(Boolean).join(' · '), urgency: l.urgency }));
  paidRefsPortal.filter((r) => r.stage !== 'Moved In' && r.stage !== 'Lost').forEach((r) => {
    if (!list.find((c) => c.name === r.prospect_name)) list.push({ id: 'ref-' + r.id, name: r.prospect_name, type: 'Paid Referral', sub: [r.source_name, r.care_level, r.prospect_phone].filter(Boolean).join(' · '), urgency: r.urgency });
  });
  REF_SOURCE_CONTACTS.forEach((c) => list.push(c));
  return list;
}
