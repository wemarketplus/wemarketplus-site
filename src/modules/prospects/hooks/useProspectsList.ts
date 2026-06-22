import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
import { useDebounce } from '@/shared/hooks';
import { PROSPECTS_FIXTURE } from '@/shared/fixtures';
import { useListProspectsQuery } from '../api/prospectsApi';
import { filterProspects, mapProspectRecord } from '../utils/prospectsUtils';

export function useProspectsList() {
  const { data, isLoading } = useListProspectsQuery();
  const search = useAppSelector((s) => s.prospects.search);
  const status = useAppSelector((s) => s.prospects.statusFilter);
  const urgency = useAppSelector((s) => s.prospects.urgencyFilter);
  const debouncedSearch = useDebounce(search, 200);

  const prospects = useMemo(
    () => (data ? data.data.map(mapProspectRecord) : PROSPECTS_FIXTURE),
    [data],
  );

  const filtered = useMemo(
    () => filterProspects(prospects, { search: debouncedSearch, status, urgency }),
    [prospects, debouncedSearch, status, urgency],
  );

  return {
    prospects: filtered,
    total: data?.total ?? prospects.length,
    isLoading,
    isUsingFixture: !data,
  };
}
