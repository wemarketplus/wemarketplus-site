import { useMemo } from 'react';
import { SENIOR_LIVING_REFERRALS_FIXTURE } from '../constants/clReferralsConstants';
import { useListClReferralSourcesQuery } from '../api/clReferralsApi';
import { toSeniorLivingReferral } from '../utils/clReferralsMappers';

export function useSeniorLivingReferrals() {
  const { data } = useListClReferralSourcesQuery();
  const live = Boolean(data && data.data.length > 0);
  const referrals = useMemo(
    () => (live ? data!.data.map(toSeniorLivingReferral) : SENIOR_LIVING_REFERRALS_FIXTURE),
    [data, live],
  );
  return { referrals, isUsingFixture: !live };
}
