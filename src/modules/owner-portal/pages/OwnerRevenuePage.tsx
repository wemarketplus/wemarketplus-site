import { Card, CardContent } from '@/shared/ui/core';
import { DataTable, type Column } from '@/shared/ui/data-display';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OWNER_REVENUE_MONTHS } from '../constants/ownerFixtures';
import { formatCompactMoney } from '../utils/ownerFormat';
import type { OwnerRevenueMonth } from '../types/ownerPortalTypes';

const columns: ReadonlyArray<Column<OwnerRevenueMonth>> = [
  {
    key: 'month',
    header: 'Month',
    cell: (m) => <span className="font-bold text-[#111]">{m.month}</span>,
  },
  { key: 'mrr', header: 'MRR', cell: (m) => formatCompactMoney(m.mrr) },
  { key: 'arr', header: 'ARR', cell: (m) => formatCompactMoney(m.arr) },
  { key: 'new', header: 'New customers', cell: (m) => m.newCustomers },
  { key: 'churned', header: 'Churned', cell: (m) => m.churned },
];

export function OwnerRevenuePage() {
  const maxMrr = Math.max(...OWNER_REVENUE_MONTHS.map((m) => m.mrr));

  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Revenue intelligence"
        description="MRR, ARR, expansion, and churn over the last 12 months."
      />

      {/* Bar chart preserved as-is. */}
      <Card dense>
        <CardContent className="px-6 py-6">
          <div className="grid grid-cols-5 items-end gap-4 sm:gap-6">
            {OWNER_REVENUE_MONTHS.map((m) => {
              const heightPct = (m.mrr / maxMrr) * 100;
              return (
                <div key={m.month} className="flex flex-col items-center gap-2">
                  <div className="flex h-44 w-full items-end overflow-hidden rounded-md bg-white/[0.04]">
                    <div
                      className="w-full rounded-md bg-gradient-to-t from-primary to-azure transition-all"
                      style={{ height: `${heightPct}%` }}
                    />
                  </div>
                  <p className="text-xs font-semibold text-foreground">{m.month}</p>
                  <p className="text-[10px] uppercase tracking-[0.1em] text-muted-soft">
                    {formatCompactMoney(m.mrr)}
                  </p>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      <DataTable columns={columns} rows={OWNER_REVENUE_MONTHS} rowKey={(m) => m.month} />
    </div>
  );
}
