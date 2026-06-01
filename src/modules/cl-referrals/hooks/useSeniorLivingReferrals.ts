import { SENIOR_LIVING_REFERRALS_FIXTURE } from '../constants/clReferralsConstants';

export function useSeniorLivingReferrals() {
  return {
    referrals: SENIOR_LIVING_REFERRALS_FIXTURE,
    isUsingFixture: true,
  };
}
