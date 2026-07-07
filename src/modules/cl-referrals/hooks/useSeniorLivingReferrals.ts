import { useMemo } from 'react';
import { useListClReferralSourcesQuery } from '../api/clReferralsApi';
import { toSeniorLivingReferral } from '../utils/clReferralsMappers';

export function useSeniorLivingReferrals() {
  const { data } = useListClReferralSourcesQuery();
  const referrals = useMemo(
    () => (data ? data.data.map(toSeniorLivingReferral) : []),
    [data],
  );
  return { referrals, isUsingFixture: false };
}
