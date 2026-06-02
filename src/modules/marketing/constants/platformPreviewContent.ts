// Static data for the "Live Platform Preview" mockup (index.html "See It
// Before You Buy"). Verbatim reproduction of the marketing dashboard screenshot.
import type {
  PreviewFeedItem,
  PreviewKpi,
  PreviewNavGroup,
  PreviewPipelineRow,
} from '../types/landingTypes';

export const PREVIEW_KPIS: readonly PreviewKpi[] = [
  { label: 'Overdue', value: '2', tone: 'text-[#f87171]' },
  { label: 'Due Today', value: '3', tone: 'text-amber' },
  { label: 'Re-Engage', value: '3', tone: 'text-azure' },
  { label: 'Admitted', value: '3', tone: 'text-sage' },
];

// Dark-enterprise badge treatment for the pipeline pills, keyed by pill tone
// (transparent tint + thin colored border + soft text). Scoped to this mockup
// so the shared Pill keeps its pastel-on-light look everywhere else it's used.
export const PREVIEW_PIPELINE_BADGE: Record<string, string> = {
  r: 'rounded-md border border-red-500/30 bg-red-500/5 px-2.5 py-1 font-semibold text-red-400',
  y: 'rounded-md border border-amber/40 bg-amber/5 px-2.5 py-1 font-semibold text-amber',
  g: 'rounded-md border border-emerald-500/30 bg-emerald-500/5 px-2.5 py-1 font-semibold text-emerald-400',
  b: 'rounded-md border border-sky-500/30 bg-sky-500/5 px-2.5 py-1 font-semibold text-sky-400',
};

export const PREVIEW_PIPELINE: readonly PreviewPipelineRow[] = [
  { name: 'Mary J.', pill: 'r', label: 'Hot', meta: 'Due Today' },
  { name: 'John T.', pill: 'y', label: 'Warm', meta: 'Due May 8' },
  { name: 'Dorothy F.', pill: 'g', label: 'Admitted', meta: 'Active' },
  { name: 'Helen P.', pill: 'b', label: 'Cold Alert', meta: '18 days' },
];

export const PREVIEW_SIDE_NAV: readonly PreviewNavGroup[] = [
  { group: 'MAIN', items: ['Dashboard'] },
  { group: 'MARKETING', items: ['Add Referral', 'Prospect Records', 'Pipeline', 'Territory View'] },
  { group: 'ACTIVITY', items: ['Notes', 'AI Assistant'] },
  { group: 'TOOLS', items: ['CSV Import', 'Referral Portal'] },
];

export const PREVIEW_FEED: readonly PreviewFeedItem[] = [
  { title: 'Reminder marked complete', detail: 'Follow-up closed', when: 'Just now', dot: 'bg-amber' },
  { title: 'New prospect added', detail: 'Assigned to team', when: 'Just now', dot: 'bg-sage' },
  { title: 'Touch logged — SNF visit', detail: 'In-Person contact', when: 'Just now', dot: 'bg-azure' },
  { title: 'Touch logged — SNF visit', detail: 'In-Person contact', when: 'Just now', dot: 'bg-azure' },
  { title: 'New prospect added', detail: 'Assigned to team', when: 'Just now', dot: 'bg-sage' },
  { title: 'Mary J. moved to Pending Admission', detail: 'Baylor Territory', when: '2m ago', dot: 'bg-sage' },
];
