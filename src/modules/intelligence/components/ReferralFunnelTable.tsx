import { DataTable, type Column } from '@/shared/ui/data-display';
import type {
  IntakeByOrigin,
  ReferralFunnelRow,
} from '../types/intelligenceTypes';
import {
  formatCount,
  formatLeadOrigin,
  formatMoney,
  formatRate,
} from '../utils/intelligenceUtils';

const funnelColumns: ReadonlyArray<Column<ReferralFunnelRow>> = [
  {
    key: 'name',
    header: 'Referral source',
    cell: (row) => (
      <div>
        <span className="font-bold text-foreground">{row.name}</span>
        <span className="block text-[11px] uppercase tracking-label text-muted-soft">
          {row.status ?? '—'}
          {row.priorityTier ? ` · tier ${row.priorityTier}` : ''}
        </span>
      </div>
    ),
  },
  { key: 'leads', header: 'Leads', cell: (row) => formatCount(row.leads) },
  {
    key: 'prospects',
    header: 'Pipelines',
    cell: (row) => formatCount(row.prospects),
  },
  { key: 'open', header: 'Open', cell: (row) => formatCount(row.open) },
  { key: 'admits', header: 'Admitted', cell: (row) => formatCount(row.admits) },
  { key: 'lost', header: 'Lost', cell: (row) => formatCount(row.lost) },
  {
    key: 'revenue',
    header: 'Revenue',
    cell: (row) => formatMoney(row.revenue),
  },
  {
    key: 'score',
    // The hand-set 1-10 account scorecard (referral_sources.aiScore). Labelled
    // "Scorecard" rather than "AI score" because nothing computes it — it is a value
    // a human types, and calling it AI would misrepresent it.
    header: 'Scorecard',
    cell: (row) => formatCount(row.score),
  },
];

export function ReferralFunnelTable({
  rows,
}: {
  rows: readonly ReferralFunnelRow[];
}) {
  return (
    <DataTable
      columns={funnelColumns}
      rows={rows}
      rowKey={(row) => row.referralSourceId}
    />
  );
}

const intakeColumns: ReadonlyArray<Column<IntakeByOrigin>> = [
  {
    key: 'sourceType',
    header: 'Origin',
    cell: (row) => (
      <span className="font-bold text-foreground">
        {formatLeadOrigin(row.sourceType)}
      </span>
    ),
  },
  { key: 'leads', header: 'Received', cell: (row) => formatCount(row.leads) },
  {
    key: 'converted',
    header: 'Converted',
    cell: (row) => formatCount(row.converted),
  },
  {
    key: 'disqualified',
    header: 'Disqualified',
    cell: (row) => formatCount(row.disqualified),
  },
  {
    key: 'conversionRate',
    header: 'Conversion',
    cell: (row) => formatRate(row.conversionRate),
  },
];

/** Intake volume by origin — the report the six lead origins were captured for. */
export function IntakeByOriginTable({
  rows,
}: {
  rows: readonly IntakeByOrigin[];
}) {
  return (
    <DataTable
      columns={intakeColumns}
      rows={rows}
      rowKey={(row) => row.sourceType}
    />
  );
}
