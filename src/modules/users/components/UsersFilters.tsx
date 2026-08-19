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
    <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
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
