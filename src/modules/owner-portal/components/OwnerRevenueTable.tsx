import { DataTable, type Column } from '@/shared/ui/data-display';
import { formatCompactMoney } from '../utils/ownerFormat';
import type { OwnerRevenueMonth, OwnerRevenueTableProps } from '../types/ownerPortalTypes';

const columns: ReadonlyArray<Column<OwnerRevenueMonth>> = [
  {
    key: 'month',
    header: 'Month',
    cell: (m) => <span className="font-bold text-foreground">{m.month}</span>,
  },
  { key: 'mrr', header: 'MRR', cell: (m) => formatCompactMoney(m.mrr) },
  { key: 'arr', header: 'ARR', cell: (m) => formatCompactMoney(m.arr) },
  { key: 'new', header: 'New customers', cell: (m) => m.newCustomers },
  { key: 'churned', header: 'Churned', cell: (m) => m.churned },
];

export function OwnerRevenueTable({ months }: OwnerRevenueTableProps) {
  return <DataTable columns={columns} rows={months} rowKey={(m) => m.month} />;
}
