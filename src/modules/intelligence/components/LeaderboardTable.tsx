import { DataTable, type Column } from '@/shared/ui/data-display';
import type { LeaderboardRow } from '../types/intelligenceTypes';

const columns: ReadonlyArray<Column<LeaderboardRow>> = [
  {
    key: 'rank',
    header: 'Rank',
    cell: (_row, i) => <span className="font-bold text-[#111]">{i + 1}</span>,
  },
  {
    key: 'marketer',
    header: 'Marketer',
    cell: (row) => <span className="font-bold text-[#111]">{row.marketer}</span>,
  },
  { key: 'admissions', header: 'Admissions', cell: (row) => row.admissions },
  {
    key: 'conversion',
    header: 'Conversion',
    cell: (row) => `${(row.conversion * 100).toFixed(0)}%`,
  },
];

export function LeaderboardTable({ rows }: { rows: readonly LeaderboardRow[] }) {
  return <DataTable columns={columns} rows={rows} rowKey={(row) => row.id} />;
}
