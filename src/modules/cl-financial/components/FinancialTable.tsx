import { DataTable, type Column } from '@/shared/ui/data-display';
import type { FinancialMonth } from '../types/clFinancialTypes';
import { formatUsd } from '../utils/financialFormat';

interface FinancialTableProps {
  months: readonly FinancialMonth[];
  // Picks which money column gets the highlighted tone. The other two are
  // shown as muted for context.
  highlight: 'revenue' | 'concessions' | 'leakage';
}

export function FinancialTable({ months, highlight }: FinancialTableProps) {
  const moneyCell = (key: FinancialTableProps['highlight'], value: number) =>
    highlight === key ? (
      <span className="font-bold text-[#111]">{formatUsd(value)}</span>
    ) : (
      <span className="text-[#667]">{formatUsd(value)}</span>
    );

  const columns: ReadonlyArray<Column<FinancialMonth>> = [
    {
      key: 'month',
      header: 'Month',
      cell: (m) => <span className="font-bold text-[#111]">{m.month}</span>,
    },
    { key: 'revenue', header: 'Revenue', cell: (m) => moneyCell('revenue', m.revenue) },
    {
      key: 'concessions',
      header: 'Concessions',
      cell: (m) => moneyCell('concessions', m.concessions),
    },
    { key: 'leakage', header: 'Leakage', cell: (m) => moneyCell('leakage', m.leakage) },
  ];

  return <DataTable columns={columns} rows={months} rowKey={(m) => m.month} />;
}
