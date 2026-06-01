import { Search } from 'lucide-react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { ALL_ROLES, ROLE_LABELS, type Role } from '@/shared/rbac';
import { Input } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import { setSearch, setSelectedRole } from '../store/usersSlice';

export function UsersFilters() {
  const dispatch = useAppDispatch();
  const search = useAppSelector((s) => s.users.search);
  const selectedRole = useAppSelector((s) => s.users.selectedRole);

  const chips: ReadonlyArray<{ value: Role | 'all'; label: string }> = [
    { value: 'all', label: 'All roles' },
    ...ALL_ROLES.map((r) => ({ value: r, label: ROLE_LABELS[r] })),
  ];

  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
      <div className="relative max-w-sm">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
        <Input
          value={search}
          onChange={(e) => dispatch(setSearch(e.target.value))}
          placeholder="Search by name or email…"
          className="pl-9"
        />
      </div>
      <div className="flex flex-wrap gap-1.5">
        {chips.map((chip) => (
          <button
            key={chip.value}
            type="button"
            onClick={() => dispatch(setSelectedRole(chip.value))}
            className={cn(
              'rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors',
              chip.value === selectedRole
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
