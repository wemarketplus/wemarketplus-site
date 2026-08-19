import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
import { useDebounce } from '@/shared/hooks';
import { useListReferralsQuery } from '../api/referralsApi';
import { filterReferrals, mapReferralSource } from '../utils/referralsUtils';

export function useReferralsList() {
  const search = useAppSelector((s) => s.referrals.search);
  const status = useAppSelector((s) => s.referrals.statusFilter);
  const coldOnly = useAppSelector((s) => s.referrals.coldOnly);
  const debouncedSearch = useDebounce(search, 200);

  // Coldness is filtered SERVER-side, unlike search and status below. It has to
  // be: "cold" is a comparison against a threshold the backend owns, and a
  // client-side filter would only ever see the current page — a marketer on page
  // 1 would be told they have no cold accounts while page 3 was full of them.
  const { data, isLoading } = useListReferralsQuery(
    coldOnly ? { cold: true } : undefined,
  );

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
    // Raw records, keyed by id — the Edit modal seeds from the full record
    // (status, priority tier, address, ...), which the `ReferralSource`
    // view-model the table renders does not carry.
    records: data?.data ?? [],
    total: data?.total ?? referrals.length,
    // Counted from the CURRENT page's rows, which is honest when the cold view
    // is on (every row is cold) and a floor otherwise. The authoritative list is
    // GET /referral-sources/cold, which the daily queue uses.
    coldCount: filtered.filter((r) => r.isCold).length,
    isLoading,
    isUsingFixture: false,
  };
}
