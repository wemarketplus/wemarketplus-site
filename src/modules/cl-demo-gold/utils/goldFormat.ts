// Pure formatting / derivation helpers for the Gold demo. No side effects, no
// API calls (per the enforced modular architecture).
import type { BadgeTone } from '@/shared/cl-demo';
import type {
  Apartment,
  AptStatus,
  HkStatus,
  HkTask,
  Lead,
  MaintStatus,
  MaintTicket,
  MrTicket,
  Urgency,
} from '../types/goldTypes';

// ── Lead tones (reference sBadge/uBadge) ─────────────────────────────
export function leadStatusTone(s: string): BadgeTone {
  if (s === 'Move-In') return 'green';
  if (s === 'Tour Scheduled') return 'blue';
  if (s === 'Proposal Sent') return 'amber';
  return 'neutral';
}

export function urgencyTone(u: Urgency): BadgeTone {
  if (u === 'High') return 'red';
  if (u === 'Medium') return 'amber';
  return 'blue';
}

// ── Make-ready helpers ───────────────────────────────────────────────
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

// ── Apartment / occupancy derivations ────────────────────────────────
export function countAptStatus(apts: readonly Apartment[], status: AptStatus): number {
  return apts.filter((a) => a.status === status).length;
}

export function occupancyRate(apts: readonly Apartment[]): number {
  return apts.length ? Math.round((countAptStatus(apts, 'occupied') / apts.length) * 100) : 0;
}

// ── Lead / maintenance / housekeeping counts ─────────────────────────
export function hotLeadCount(leads: readonly Lead[]): number {
  return leads.filter((l) => l.urgency === 'High').length;
}

export function activeLeadCount(leads: readonly Lead[]): number {
  return leads.filter((l) => l.status !== 'Move-In').length;
}

export function hotLeads(leads: readonly Lead[]): Lead[] {
  return leads.filter((l) => l.urgency === 'High');
}

export function countMaint(tickets: readonly MaintTicket[], status: MaintStatus): number {
  return tickets.filter((t) => t.status === status).length;
}

export function openMaintCount(tickets: readonly MaintTicket[]): number {
  return tickets.filter((t) => t.status !== 'completed').length;
}

export function countHk(tasks: readonly HkTask[], status: HkStatus): number {
  return tasks.filter((t) => t.status === status).length;
}

export function openHkCount(tasks: readonly HkTask[]): number {
  return tasks.filter((t) => t.status !== 'completed').length;
}

export function openMrCount(tickets: readonly MrTicket[]): number {
  return tickets.filter((t) => t.pct < 100).length;
}

// Task list row class (reference rTasks row styling; dims completed rows).
export function taskRowClass(done: boolean): string {
  return `mb-[7px] flex items-center gap-[11px] rounded-[10px] border border-white/[0.05] bg-[#071120] px-[13px] py-[11px]${done ? ' opacity-50' : ''}`;
}
