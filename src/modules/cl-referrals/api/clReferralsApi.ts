// TODO(backend): /senior-living/referrals.
import type { SeniorLivingReferral } from '../types/clReferralsTypes';

const SENIOR_LIVING_REFERRALS_FIXTURE: readonly SeniorLivingReferral[] = [
  {
    id: 'slr-001',
    name: 'Dr. Beatrice Lin',
    organization: 'St. Joseph General Practice',
    email: 'b.lin@stjosephgp.com',
    phone: '(415) 555-7700',
    source: 'physician',
    rating: 5,
    notes: 'Steady stream of memory-care referrals.',
  },
  {
    id: 'slr-002',
    name: 'Hank Russo',
    organization: 'Westside Adult Day Center',
    email: 'hank@westsideadc.org',
    phone: '(415) 555-7711',
    source: 'community',
    rating: 4,
  },
  {
    id: 'slr-003',
    name: 'Vera Khalid',
    organization: 'Family inquiry',
    email: 'vera@khalidfamily.us',
    phone: '(415) 555-7722',
    source: 'family',
    rating: 3,
  },
];

export function getSeniorLivingReferrals(): readonly SeniorLivingReferral[] {
  return SENIOR_LIVING_REFERRALS_FIXTURE;
}
