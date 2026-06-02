import { useMemo, useState } from 'react';
import { useAppSelector } from '@/app/hooks';
import { useDebounce } from '@/shared/hooks';
import { useListUsersQuery } from '../api/usersApi';
import { DEFAULT_PAGE_SIZE } from '../constants/usersConstants';

// Composes the paginated list query with the local UI filters (search + role).
// Search is client-side for now — backend doesn't expose a search param yet.
export function useUsersList() {
  const [page, setPage] = useState(1);
  const search = useAppSelector((s) => s.users.search);
  const selectedRole = useAppSelector((s) => s.users.selectedRole);
  const debouncedSearch = useDebounce(search, 250);

  const query = useListUsersQuery({ page, limit: DEFAULT_PAGE_SIZE });

  const filtered = useMemo(() => {
    if (!query.data) return [];
    const needle = debouncedSearch.trim().toLowerCase();
    return query.data.data.filter((u) => {
      if (selectedRole !== 'all' && u.role !== selectedRole) return false;
      if (!needle) return true;
      return (
        u.email.toLowerCase().includes(needle) ||
        `${u.firstName} ${u.lastName}`.toLowerCase().includes(needle)
      );
    });
  }, [query.data, debouncedSearch, selectedRole]);

  const total = query.data?.total ?? 0;
  const lastPage = Math.max(1, Math.ceil(total / DEFAULT_PAGE_SIZE));

  return {
    users: filtered,
    total,
    page,
    pageSize: DEFAULT_PAGE_SIZE,
    lastPage,
    setPage,
    isLoading: query.isLoading,
    isFetching: query.isFetching,
    error: query.error,
    refetch: query.refetch,
  };
}
