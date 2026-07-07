import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
import { useDebounce } from '@/shared/hooks';
import { useListReferralsQuery } from '../api/referralsApi';
import { filterReferrals, mapReferralSource } from '../utils/referralsUtils';

export function useReferralsList() {
  const { data, isLoading } = useListReferralsQuery();
  const search = useAppSelector((s) => s.referrals.search);
  const status = useAppSelector((s) => s.referrals.statusFilter);
  const debouncedSearch = useDebounce(search, 200);

  const referrals = useMemo(
    () => (data ? data.data.map(mapReferralSource) : []),
    [data],
  );

  const filtered = useMemo(
    () => filterReferrals(referrals, { search: debouncedSearch, status }),
    [referrals, debouncedSearch, status],
  );

  return {
    referrals: filtered,
    total: data?.total ?? referrals.length,
    isLoading,
    isUsingFixture: false,
  };
}
