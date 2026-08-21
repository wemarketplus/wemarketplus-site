// Pure formatting / derivation helpers for the CommunityLink demo. No side
// effects, no API calls (per the enforced modular architecture).
import { IRS_RATE, SNAPSHOT_STAGES, STAGES } from '../constants/clDemoNav';
import type {
  BadgeTone,
  Lead,
  MileageEntry,
  PipelineSnapshotRow,
  SourceChartRow,
  Task,
  Urgency,
} from '../types/clDemoTypes';

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
  if (u === 'High') return 'red';
  if (u === 'Medium') return 'amber';
  return 'blue';
}

// Counts of active (non-terminal) leads — reference rDash active count.
export function activeLeadCount(leads: readonly Lead[]): number {
  return leads.filter((l) => l.status !== 'Move-In' && l.status !== 'Lost').length;
}

export function hotLeads(leads: readonly Lead[]): Lead[] {
  return leads.filter((l) => l.urgency === 'High');
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

// Open (incomplete) tasks — shared by the dashboard count, task manager count,
// and the "Tasks Due Today" card.
export function openTasks(tasks: readonly Task[]): Task[] {
  return tasks.filter((t) => !t.done);
}

// Sum of logged miles (dashboard + mileage tracker totals).
export function totalMiles(mileage: readonly MileageEntry[]): number {
  return mileage.reduce((s, m) => s + m.miles, 0);
}

// Lead pipeline search/stage/urgency filter (reference rLeads() filtering).
export function filterLeads(
  leads: readonly Lead[],
  q: string,
  status: string,
  urg: string,
): Lead[] {
  return leads.filter(
    (l) =>
      (!q || (l.name + l.care + l.status + l.source).toLowerCase().includes(q.toLowerCase())) &&
      (!status || l.status === status) &&
      (!urg || l.urgency === urg),
  );
}
