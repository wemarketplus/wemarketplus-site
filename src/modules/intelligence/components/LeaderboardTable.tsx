import { DataTable, type Column } from '@/shared/ui/data-display';
import type { LeaderboardRow } from '../types/intelligenceTypes';
import {
  formatCount,
  formatMoney,
  formatRate,
} from '../utils/intelligenceUtils';

// Rank comes from the server, which orders by admits then attributed revenue then
// touches then id — deterministic, so the same data always ranks the same way. The
// table does NOT re-sort: a client-side sort could disagree with the rank number in
// the first column.
const columns: ReadonlyArray<Column<LeaderboardRow>> = [
  {
    key: 'rank',
    header: 'Rank',
    cell: (row) => <span className="font-bold text-foreground">{row.rank}</span>,
  },
  {
    key: 'name',
    header: 'Rep',
    cell: (row) => (
      <div>
        <span className="font-bold text-foreground">{row.name || row.email}</span>
        <span className="block text-[11px] uppercase tracking-label text-muted-soft">
          {row.role}
        </span>
      </div>
    ),
  },
  { key: 'admits', header: 'Admits', cell: (row) => formatCount(row.admits) },
  {
    key: 'revenue',
    header: 'Attributed revenue',
    cell: (row) => formatMoney(row.revenue),
  },
  { key: 'touches', header: 'Touches', cell: (row) => formatCount(row.touches) },
  {
    key: 'jobsCompleted',
    header: 'Jobs done',
    cell: (row) => formatCount(row.jobsCompleted),
  },
  {
    key: 'goalPace',
    header: 'Goal pace',
    // null = this rep has no goals set, which is not the same as 0% progress.
    cell: (row) => formatRate(row.goalPace),
  },
];

export function LeaderboardTable({ rows }: { rows: readonly LeaderboardRow[] }) {
  return (
    <DataTable columns={columns} rows={rows} rowKey={(row) => row.userId} />
  );
}
