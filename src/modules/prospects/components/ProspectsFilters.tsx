import { Search } from 'lucide-react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { Input } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import {
  STATUS_CHIPS,
  URGENCY_CHIPS,
} from '../constants/prospectsConstants';
import {
  setProspectSearch,
  setStatusFilter,
  setUrgencyFilter,
} from '../store/prospectsSlice';

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
                : 'border-border/[0.08] text-muted hover:border-border/20 hover:text-foreground',
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
                : 'border-border/[0.08] text-muted hover:border-border/20 hover:text-foreground',
            )}
          >
            {chip.label}
          </button>
        ))}
      </div>
    </div>
  );
}
