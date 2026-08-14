import type { ReportDefinition } from '../types/clReportsTypes';

export const REPORT_CATALOG: readonly ReportDefinition[] = [
  // The two reports the end-user guide promises a Sales Marketer. Available on
  // every CommunityLink tier — they are computed from cl_leads and cl_tours, which
  // Pro already has. Listed first because for a marketer they are the whole screen.
  {
    id: 'r-leads-by-source',
    title: 'Leads by source',
    description: 'Where every lead came from, ranked, with each source’s share.',
    category: 'sales',
  },
  {
    id: 'r-tour-conversion',
    title: 'Tour-to-move-in conversion',
    description:
      'What share of completed tours became move-ins, plus no-shows and tours still booked.',
    category: 'sales',
  },
  {
    id: 'r-occupancy',
    title: 'Occupancy summary',
    description: 'Unit-by-unit occupancy plus 30-day move-in/move-out trend.',
    category: 'occupancy',
    lastRunAt: '2026-05-22T18:00:00Z',
  },
  {
    id: 'r-revenue',
    title: 'Revenue per resident',
    description: 'Average revenue per resident segmented by care level.',
    category: 'revenue',
    lastRunAt: '2026-05-20T18:00:00Z',
  },
  {
    id: 'r-leakage',
    title: 'Revenue leakage',
    description: 'Missed billables, concessions, and downgrades.',
    category: 'revenue',
  },
  {
    id: 'r-make-ready',
    title: 'Make-ready cycle time',
    description: 'Average days from move-out to ready-to-show.',
    category: 'operations',
  },
  {
    id: 'r-maintenance',
    title: 'Maintenance SLA',
    description: 'Response and resolution times by priority.',
    category: 'operations',
    lastRunAt: '2026-05-19T18:00:00Z',
  },
  {
    id: 'r-compliance',
    title: 'Compliance attestations',
    description: 'Staff certification status and renewal dates.',
    category: 'compliance',
  },
];

export const CATEGORY_LABEL: Record<ReportDefinition['category'], string> = {
  sales: 'Sales',
  occupancy: 'Occupancy',
  revenue: 'Revenue',
  operations: 'Operations',
  compliance: 'Compliance',
};

export const CATEGORY_ORDER: ReadonlyArray<ReportDefinition['category']> = [
  'sales',
  'occupancy',
  'revenue',
  'operations',
  'compliance',
];
