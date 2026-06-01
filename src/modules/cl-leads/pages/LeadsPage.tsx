import { Plus } from 'lucide-react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { LeadStatus } from '@/shared/types';
import { Button } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import { LEAD_STATUS_LABELS } from '../constants/leadsConstants';
import { LeadsTable } from '../components/LeadsTable';
import { AddLeadModal } from '../components/AddLeadModal';
import { useLeadsList } from '../hooks/useLeadsList';
import { openAddLead, setLeadStatusFilter } from '../store/leadsSlice';

const CHIPS: ReadonlyArray<{ value: LeadStatus | 'all'; label: string }> = [
  { value: 'all', label: 'All' },
  ...Object.values(LeadStatus).map((s) => ({
    value: s,
    label: LEAD_STATUS_LABELS[s],
  })),
];

export function LeadsPage() {
  const dispatch = useAppDispatch();
  const status = useAppSelector((s) => s.clLeads.statusFilter);
  const { leads, total, isUsingFixture } = useLeadsList();

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="font-display text-3xl text-foreground">Lead pipeline</h1>
          <p className="text-sm text-muted">
            {total} leads across the senior-living pipeline
            {isUsingFixture && (
              <span className="ml-2 rounded-pill bg-white/[0.04] px-2 py-0.5 text-[10px] uppercase tracking-[0.1em] text-muted-soft">
                Preview data
              </span>
            )}
          </p>
        </div>
        <Button onClick={() => dispatch(openAddLead())}>
          <Plus className="h-4 w-4" /> Add Lead
        </Button>
      </header>

      <div className="flex flex-wrap gap-1.5">
        {CHIPS.map((c) => (
          <button
            key={c.value}
            type="button"
            onClick={() => dispatch(setLeadStatusFilter(c.value))}
            className={cn(
              'rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors',
              status === c.value
                ? 'border-primary/40 bg-primary/15 text-primary'
                : 'border-white/[0.08] text-muted hover:border-white/20 hover:text-foreground',
            )}
          >
            {c.label}
          </button>
        ))}
      </div>

      <LeadsTable leads={leads} />
      <AddLeadModal />
    </div>
  );
}
