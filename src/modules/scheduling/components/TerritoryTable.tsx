import { DataTable, type Column } from '@/shared/ui/data-display';
import type { Territory } from '@/shared/types';
import { totalAdmissions } from '../utils/schedulingUtils';

// The table shows each territory plus a trailing "Total" summary row. We model
// the summary as a sentinel row so it can flow through DataTable's renderer.
type TotalRow = { id: '__total__'; admissionsCount: number };
type Row = Territory | TotalRow;

const isTotal = (r: Row): r is TotalRow => r.id === '__total__';

const columns: ReadonlyArray<Column<Row>> = [
  {
    key: 'territory',
    header: 'Territory',
    cell: (r) =>
      isTotal(r) ? <span className="font-bold text-[#111]">Total</span> : (
        <span className="font-bold text-[#111]">{r.areaName}</span>
      ),
  },
  { key: 'marketer', header: 'Marketer', cell: (r) => (isTotal(r) ? '' : r.assignedMarketer) },
  { key: 'accounts', header: 'Accounts', cell: (r) => (isTotal(r) ? '' : r.primaryAccounts) },
  { key: 'visits', header: 'Visits', cell: (r) => (isTotal(r) ? '' : r.visitsCount) },
  {
    key: 'admissions',
    header: 'Admissions',
    cell: (r) =>
      isTotal(r) ? (
        <span className="font-bold text-[#111]">{r.admissionsCount}</span>
      ) : (
        r.admissionsCount
      ),
  },
  {
    key: 'conversion',
    header: 'Conversion',
    cell: (r) => (isTotal(r) ? '' : `${(r.conversionRate * 100).toFixed(0)}%`),
  },
];

export function TerritoryTable({ territories }: { territories: readonly Territory[] }) {
  const rows: Row[] = [
    ...territories,
    { id: '__total__', admissionsCount: totalAdmissions(territories) },
  ];
  return <DataTable columns={columns} rows={rows} rowKey={(r) => r.id} />;
}
