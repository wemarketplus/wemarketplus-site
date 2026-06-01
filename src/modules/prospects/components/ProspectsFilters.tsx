import { Search } from 'lucide-react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { ProspectStatus, Urgency } from '@/shared/types';
import { Input } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import {
  PROSPECT_STATUS_LABELS,
  URGENCY_LABELS,
} from '../constants/prospectsConstants';
import {
  setProspectSearch,
  setStatusFilter,
  setUrgencyFilter,
} from '../store/prospectsSlice';

const STATUS_CHIPS: ReadonlyArray<{ value: ProspectStatus | 'all'; label: string }> = [
  { value: 'all', label: 'All statuses' },
  { value: ProspectStatus.Inquiry, label: PROSPECT_STATUS_LABELS.inquiry },
  { value: ProspectStatus.PendingAdmission, label: PROSPECT_STATUS_LABELS.pending_admission },
  { value: ProspectStatus.Admitted, label: PROSPECT_STATUS_LABELS.admitted },
  { value: ProspectStatus.Lost, label: PROSPECT_STATUS_LABELS.lost },
];

const URGENCY_CHIPS: ReadonlyArray<{ value: Urgency | 'all'; label: string }> = [
  { value: 'all', label: 'Any urgency' },
  { value: Urgency.Hot, label: URGENCY_LABELS.hot },
  { value: Urgency.Warm, label: URGENCY_LABELS.warm },
  { value: Urgency.Cold, label: URGENCY_LABELS.cold },
];

export function ProspectsFilters() {
  const dispatch = useAppDispatch();
  const search = useAppSelector((s) => s.prospects.search);
  const status = useAppSelector((s) => s.prospects.statusFilter);
  const urgency = useAppSelector((s) => s.prospects.urgencyFilter);

  return (
    <div className="space-y-3">
      <div className="relative max-w-sm">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
        <Input
          value={search}
          onChange={(e) => dispatch(setProspectSearch(e.target.value))}
          placeholder="Search by name, email, or source…"
          className="pl-9"
        />
      </div>
      <div className="flex flex-wrap gap-1.5">
        {STATUS_CHIPS.map((chip) => (
          <button
            key={chip.value}
            type="button"
            onClick={() => dispatch(setStatusFilter(chip.value))}
            className={cn(
              'rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors',
              status === chip.value
                ? 'border-primary/40 bg-primary/15 text-primary'
                : 'border-white/[0.08] text-muted hover:border-white/20 hover:text-foreground',
            )}
          >
            {chip.label}
          </button>
        ))}
      </div>
      <div className="flex flex-wrap gap-1.5">
        {URGENCY_CHIPS.map((chip) => (
          <button
            key={chip.value}
            type="button"
            onClick={() => dispatch(setUrgencyFilter(chip.value))}
            className={cn(
              'rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors',
              urgency === chip.value
                ? 'border-azure/40 bg-azure/15 text-azure'
                : 'border-white/[0.08] text-muted hover:border-white/20 hover:text-foreground',
            )}
          >
            {chip.label}
          </button>
        ))}
      </div>
    </div>
  );
}
