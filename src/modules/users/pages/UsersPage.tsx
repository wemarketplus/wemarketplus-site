import { extractApiErrorMessage } from '@/modules/auth/utils/errorUtils';
import { Card, CardContent } from '@/shared/ui/core';
import { useUsersList } from '../hooks/useUsersList';
import { UsersFilters } from '../components/UsersFilters';
import { UsersTable } from '../components/UsersTable';

export function UsersPage() {
  const { users, total, page, pageSize, setPage, isLoading, isFetching, error } =
    useUsersList();

  const lastPage = Math.max(1, Math.ceil(total / pageSize));

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-1">
        <h1 className="font-display text-3xl text-foreground">Team members</h1>
        <p className="text-sm text-muted">
          {total} {total === 1 ? 'user' : 'users'} across your CRM. Filter or search to
          narrow the list.
        </p>
      </div>

      <Card>
        <CardContent className="space-y-5 pt-6">
          <UsersFilters />

          {error && (
            <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3.5 py-2.5 text-sm text-destructive">
              {extractApiErrorMessage(error, 'Failed to load users')}
            </p>
          )}

          <UsersTable users={users} isLoading={isLoading} />

          <div className="flex items-center justify-between text-xs text-muted-soft">
            <span className="uppercase tracking-[0.1em]">
              Page {page} of {lastPage}
              {isFetching && page > 1 ? ' · refreshing…' : ''}
            </span>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="rounded-pill border border-white/[0.08] px-3.5 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] text-muted transition-colors hover:border-white/20 hover:text-foreground disabled:opacity-40 disabled:hover:border-white/[0.08] disabled:hover:text-muted"
              >
                Previous
              </button>
              <button
                type="button"
                onClick={() => setPage((p) => Math.min(lastPage, p + 1))}
                disabled={page >= lastPage}
                className="rounded-pill border border-white/[0.08] px-3.5 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] text-muted transition-colors hover:border-white/20 hover:text-foreground disabled:opacity-40 disabled:hover:border-white/[0.08] disabled:hover:text-muted"
              >
                Next
              </button>
            </div>
          </div>
        </CardContent>
      </Card>

    </div>
  );
}
