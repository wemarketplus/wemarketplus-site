import { useMemo } from 'react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { useDebounce } from '@/shared/hooks';
import { useListLeadsQuery } from '../api/leadsApi';
import {
  setSearch,
  setSourceFilter,
  setStatusFilter,
} from '../store/leadsSlice';
import type { LeadSourceType, LeadStatus } from '../types/leadsTypes';

/**
 * Leads list. Filtering is SERVER-side (the backend list query supports search +
 * status + sourceType), so the debounced needle goes into the request rather than
 * filtering a page of results on the client.
 */
export function useLeadsList() {
  const dispatch = useAppDispatch();
  const search = useAppSelector((s) => s.leads.search);
  const statusFilter = useAppSelector((s) => s.leads.statusFilter);
  const sourceFilter = useAppSelector((s) => s.leads.sourceFilter);
  const debouncedSearch = useDebounce(search, 250);

  const query = useMemo(
    () => ({
      search: debouncedSearch.trim() || undefined,
      status: statusFilter === 'all' ? undefined : statusFilter,
      sourceType: sourceFilter === 'all' ? undefined : sourceFilter,
    }),
    [debouncedSearch, statusFilter, sourceFilter],
  );

  const { data, isLoading, isFetching, isError } = useListLeadsQuery(query);

  return {
    leads: data?.data ?? [],
    total: data?.total ?? 0,
    isLoading,
    isFetching,
    isError,
    search,
    statusFilter,
    sourceFilter,
    setSearch: (value: string) => dispatch(setSearch(value)),
    setStatusFilter: (value: LeadStatus | 'all') =>
      dispatch(setStatusFilter(value)),
    setSourceFilter: (value: LeadSourceType | 'all') =>
      dispatch(setSourceFilter(value)),
  };
}
