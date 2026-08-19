import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
import {
  useDebounce,
  useReferralSourceNames,
  useUserNames,
} from '@/shared/hooks';
import { useListProspectsQuery } from '../api/prospectsApi';
import { filterProspects, mapProspectRecord } from '../utils/prospectsUtils';

export function useProspectsList() {
  const { data, isLoading } = useListProspectsQuery();
  const search = useAppSelector((s) => s.prospects.search);
  const status = useAppSelector((s) => s.prospects.statusFilter);
  const urgency = useAppSelector((s) => s.prospects.urgencyFilter);
  const debouncedSearch = useDebounce(search, 200);

  // A prospect row stores only `referralSourceId` and `assignedTo`. These two
  // tables turn those ids into the names the Source and Marketer columns show —
  // without them the table rendered raw uuids.
  const referralSources = useReferralSourceNames();
  const users = useUserNames();

  const names = useMemo(
    () => ({ referralSources, users }),
    [referralSources, users],
  );

  const prospects = useMemo(
    () => (data ? data.data.map((r) => mapProspectRecord(r, names)) : []),
    [data, names],
  );

  const filtered = useMemo(
    () => filterProspects(prospects, { search: debouncedSearch, status, urgency }),
    [prospects, debouncedSearch, status, urgency],
  );

  return {
    prospects: filtered,
    // Raw records, keyed by id — the Edit modal seeds from the full record
    // (facility, physician, diagnosis, ...), which the `Prospect` view-model
    // the table renders does not carry.
    records: data?.data ?? [],
    total: data?.total ?? 0,
    isLoading,
    isUsingFixture: false,
  };
}
