import { DataTable, type Column } from '@/shared/ui/data-display';
import type { MarketingRoiBySource } from '../types/intelligenceTypes';
import {
  formatCount,
  formatMoney,
  formatMoneyPerUnit,
  formatRate,
} from '../utils/intelligenceUtils';

// Effort-based, not spend-based: the product tracks no marketing budget anywhere, so
// "touches" (logged interactions + completed visits + completed jobs) is the
// denominator. The page states this above the table so the numbers are not read as a
// currency-denominated ROI.
const columns: ReadonlyArray<Column<MarketingRoiBySource>> = [
  {
    key: 'name',
    header: 'Referral source',
    cell: (row) => <span className="font-bold text-foreground">{row.name}</span>,
  },
  {
    key: 'touches',
    header: 'Touches',
    cell: (row) => (
      <div>
        <span>{formatCount(row.touches)}</span>
        <span className="block text-[11px] text-muted-soft">
          {row.notes} notes · {row.visits} visits · {row.jobsCompleted} jobs
        </span>
      </div>
    ),
  },
  {
    key: 'prospects',
    header: 'Pipelines',
    cell: (row) => (
      <div>
        <span>{formatCount(row.prospects)}</span>
        <span className="block text-[11px] text-muted-soft">
          {row.admits} admitted · {row.lost} lost
        </span>
      </div>
    ),
  },
  {
    key: 'conversionRate',
    header: 'Conversion',
    cell: (row) => formatRate(row.conversionRate),
  },
  {
    key: 'revenue',
    header: 'Revenue',
    cell: (row) => formatMoney(row.revenue),
  },
  {
    key: 'revenuePerTouch',
    header: 'Per touch',
    cell: (row) => formatMoneyPerUnit(row.revenuePerTouch),
  },
  {
    key: 'touchesPerAdmit',
    header: 'Touches / admit',
    cell: (row) => formatCount(row.touchesPerAdmit),
  },
];

export function MarketingRoiTable({
  rows,
}: {
  rows: readonly MarketingRoiBySource[];
}) {
  return (
    <DataTable
      columns={columns}
      rows={rows}
      rowKey={(row) => row.referralSourceId}
    />
  );
}
