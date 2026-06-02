// Pure formatting / derivation helpers for the CommunityLink demo. No side
// effects, no API calls (per the enforced modular architecture).
import { IRS_RATE, STAGES } from '../constants/clDemoNav';
import type { BadgeTone, Lead, LeadStatus, Urgency } from '../types/clDemoTypes';

export function cap(s: string): string {
  if (!s) return '';
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// Dollar reimbursement for a mileage figure (matches `$' + (miles*0.67)`).
export function reimbursable(miles: number, digits = 2): string {
  return (miles * IRS_RATE).toFixed(digits);
}

// Maps a lead status to its badge tone (reference statusBadge()).
export function statusBadgeTone(s: string): BadgeTone {
  if (s === 'Move-In') return 'green';
  if (s === 'Tour Scheduled') return 'blue';
  if (s === 'Proposal Sent') return 'amber';
  if (s === 'Lost') return 'red';
  return 'neutral';
}

// Maps urgency to its badge tone (reference urgBadge()).
export function urgencyBadgeTone(u: Urgency): BadgeTone {
  if (u === 'Hot') return 'red';
  if (u === 'Warm') return 'amber';
  return 'blue';
}

// Counts of active (non-terminal) leads — reference rDash active count.
export function activeLeadCount(leads: readonly Lead[]): number {
  return leads.filter((l) => l.status !== 'Move-In' && l.status !== 'Lost').length;
}

export function hotLeads(leads: readonly Lead[]): Lead[] {
  return leads.filter((l) => l.urgency === 'Hot');
}

export function moveInCount(leads: readonly Lead[]): number {
  return leads.filter((l) => l.status === 'Move-In').length;
}

// Per-stage lead counts for the Pipeline Overview strip.
export function stageCounts(leads: readonly Lead[]): Record<string, number> {
  const counts: Record<string, number> = {};
  STAGES.forEach((s) => {
    counts[s] = leads.filter((l) => l.status === s).length;
  });
  return counts;
}

export interface SourceChartRow {
  source: string;
  count: number;
  pct: number;
}

// Top-5 leads-by-source rows (reference buildSourceChart()), normalized so the
// largest bar is 100%.
export function bySourceChart(leads: readonly Lead[]): SourceChartRow[] {
  const counts: Record<string, number> = {};
  leads.forEach((l) => {
    counts[l.source] = (counts[l.source] || 0) + 1;
  });
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const max = sorted[0] ? sorted[0][1] : 1;
  return sorted.slice(0, 5).map(([source, count]) => ({
    source,
    count,
    pct: (count / max) * 100,
  }));
}

export interface PipelineSnapshotRow {
  stage: LeadStatus;
  count: number;
  pct: number;
}

const SNAPSHOT_STAGES: LeadStatus[] = ['Inquiry', 'Follow-up', 'Tour Scheduled', 'Proposal Sent', 'Move-In'];

// Reports tab pipeline snapshot table (% of all leads in each stage).
export function pipelineSnapshot(leads: readonly Lead[]): PipelineSnapshotRow[] {
  return SNAPSHOT_STAGES.map((stage) => {
    const count = leads.filter((l) => l.status === stage).length;
    return {
      stage,
      count,
      pct: leads.length ? Math.round((count / leads.length) * 100) : 0,
    };
  });
}
