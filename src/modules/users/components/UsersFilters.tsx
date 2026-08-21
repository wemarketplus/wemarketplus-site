import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { SearchInput } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import { ROLE_FILTER_CHIPS } from '../constants/usersConstants';
import { setSearch, setSelectedRole } from '../store/usersSlice';

export function UsersFilters() {
  const dispatch = useAppDispatch();
  const search = useAppSelector((s) => s.users.search);
  const selectedRole = useAppSelector((s) => s.users.selectedRole);

  return (
    /**
     * The search box gets its OWN row above the chips, matching the prospects and
     * referral-source filter bars.
     *
     * It used to sit beside them in a `sm:flex-row sm:justify-between` row, where
     * it had `max-w-sm` (a cap) but no width and no `flex-1` (a floor). A cap does
     * not stop flex shrinking, and the sibling is a wrapping group of thirteen role
     * chips whose content width is far more than the row can hold — so the input
     * was squeezed to 145px of a 1057px row. At that size neither the placeholder
     * nor a typed name fits: "Search by name or email…" rendered as "Search by nar",
     * and searching for a team member hid the very text you were typing.
     *
     * Stacking is what actually fixes it. Adding `flex-1` would only have traded
     * one cramped control for two, since the chips genuinely need a full row.
     */
    <div className="space-y-3">
      <SearchInput
        wrapperClassName="max-w-sm"
        value={search}
        onChange={(value) => dispatch(setSearch(value))}
        placeholder="Search by name or email…"
      />
      <div className="flex flex-wrap gap-1.5">
        {ROLE_FILTER_CHIPS.map((chip) => (
          <button
            key={chip.value}
            type="button"
            onClick={() => dispatch(setSelectedRole(chip.value))}
            className={cn(
              'rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors',
              chip.value === selectedRole
                ? 'border-primary/40 bg-primary/15 text-primary'
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
