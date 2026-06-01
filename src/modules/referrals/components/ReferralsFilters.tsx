import { Search } from 'lucide-react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { ReferralSourceStatus } from '@/shared/types';
import { Input } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import { REFERRAL_STATUS_LABELS } from '../constants/referralsConstants';
import {
  setReferralSearch,
  setReferralStatusFilter,
} from '../store/referralsSlice';

const CHIPS: ReadonlyArray<{ value: ReferralSourceStatus | 'all'; label: string }> = [
  { value: 'all', label: 'All statuses' },
  { value: ReferralSourceStatus.Green, label: REFERRAL_STATUS_LABELS.green },
  { value: ReferralSourceStatus.Building, label: REFERRAL_STATUS_LABELS.building },
  { value: ReferralSourceStatus.Red, label: REFERRAL_STATUS_LABELS.red },
];

export function ReferralsFilters() {
  const dispatch = useAppDispatch();
  const search = useAppSelector((s) => s.referrals.search);
  const status = useAppSelector((s) => s.referrals.statusFilter);

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
        {CHIPS.map((chip) => (
          <button
            key={chip.value}
            type="button"
            onClick={() => dispatch(setReferralStatusFilter(chip.value))}
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
    </div>
  );
}
