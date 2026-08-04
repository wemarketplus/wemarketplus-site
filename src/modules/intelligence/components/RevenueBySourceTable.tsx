import { DataTable, type Column } from '@/shared/ui/data-display';
import type { RevenueBySource } from '../types/intelligenceTypes';
import { formatCount, formatMoney } from '../utils/intelligenceUtils';

// This table is the answer to the question the product could not answer at all until
// invoices carried a referralSourceId: "which hospital produced this revenue?"
const columns: ReadonlyArray<Column<RevenueBySource>> = [
  {
    key: 'name',
    header: 'Referral source',
    cell: (row) => (
      <div>
        <span className="font-bold text-foreground">{row.name}</span>
        {row.priorityTier && (
          <span className="block text-[11px] uppercase tracking-[0.08em] text-muted-soft">
            Tier {row.priorityTier}
          </span>
        )}
      </div>
    ),
  },
  { key: 'admits', header: 'Admits', cell: (row) => formatCount(row.admits) },
  {
    key: 'invoiced',
    header: 'Billed',
    cell: (row) => formatMoney(row.invoiced),
  },
  { key: 'paid', header: 'Collected', cell: (row) => formatMoney(row.paid) },
  {
    key: 'outstanding',
    header: 'Outstanding',
    cell: (row) => formatMoney(row.outstanding),
  },
  {
    key: 'contractValue',
    header: 'Contract value',
    cell: (row) => formatMoney(row.contractValue),
  },
];

export function RevenueBySourceTable({
  rows,
}: {
  rows: readonly RevenueBySource[];
}) {
  return (
    <DataTable
      columns={columns}
      rows={rows}
      rowKey={(row) => row.referralSourceId}
    />
  );
}
