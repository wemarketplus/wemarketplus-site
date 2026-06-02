import { getSeniorLivingReferrals } from '../api/clReferralsApi';

export function useSeniorLivingReferrals() {
  return {
    referrals: getSeniorLivingReferrals(),
    isUsingFixture: true,
  };
}
