import { useMemo } from 'react';

interface PaginatedQueryResult<T> {
  data?: { data: T[]; total: number };
  isLoading: boolean;
  isFetching: boolean;
  error?: unknown;
}

interface UsePaginatedListOptions<T> {
  pageSize: number;
  // Optional client-side predicate (search/filter chips). The backend paginates;
  // this narrows the current page further. Return true to keep the row.
  filter?: (row: T) => boolean;
}

// Derives the presentational bits of a paginated list — filtered rows, total,
// and lastPage — from an RTK Query result. Page state stays with the caller
// (which must feed `page` into its list query so the server paginates); this
// hook is deliberately state-free to avoid a page/query circular dependency.
// The caller keeps `page` in a `useState` and derives prev/next from `lastPage`
// (see modules/contacts/hooks/useContacts.ts).
export function usePaginatedList<T>(
  query: PaginatedQueryResult<T>,
  { pageSize, filter }: UsePaginatedListOptions<T>,
) {
  const rows = useMemo(() => {
    const all = query.data?.data ?? [];
    return filter ? all.filter(filter) : all;
  }, [query.data, filter]);

  const total = query.data?.total ?? 0;
  const lastPage = Math.max(1, Math.ceil(total / pageSize));

  return {
    rows,
    total,
    lastPage,
    isLoading: query.isLoading,
    isFetching: query.isFetching,
    error: query.error,
  };
}
