import { Search } from 'lucide-react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { Input } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import { REFERRAL_FILTER_CHIPS } from '../constants/referralsConstants';
import {
  setReferralColdOnly,
  setReferralSearch,
  setReferralStatusFilter,
} from '../store/referralsSlice';

export function ReferralsFilters() {
  const dispatch = useAppDispatch();
  const search = useAppSelector((s) => s.referrals.search);
  const status = useAppSelector((s) => s.referrals.statusFilter);
  const coldOnly = useAppSelector((s) => s.referrals.coldOnly);

  return (
    <div className="space-y-3">
      <div className="relative max-w-sm">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
        <Input
          value={search}
          onChange={(e) => dispatch(setReferralSearch(e.target.value))}
          placeholder="Search referral sources…"
          className="pl-9"
        />
      </div>
      <div className="flex flex-wrap gap-1.5">
        {REFERRAL_FILTER_CHIPS.map((chip) => (
          <button
            key={chip.value}
            type="button"
            onClick={() => dispatch(setReferralStatusFilter(chip.value))}
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

        {/* A separate toggle rather than another status chip: coldness is a
            different axis from the account's lifecycle status, and an
            active_referrer nobody has visited in three weeks is still cold. */}
        <button
          type="button"
          onClick={() => dispatch(setReferralColdOnly(!coldOnly))}
          aria-pressed={coldOnly}
          className={cn(
            'rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors',
            coldOnly
              ? 'border-destructive/40 bg-destructive/15 text-destructive'
              : 'border-border/[0.08] text-muted hover:border-border/20 hover:text-foreground',
          )}
        >
          Cold only
        </button>
      </div>
    </div>
  );
}
