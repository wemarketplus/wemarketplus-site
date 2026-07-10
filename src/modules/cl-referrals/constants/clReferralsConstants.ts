import type { SeniorLivingReferral } from '../types/clReferralsTypes';

export const SOURCE_LABEL: Record<SeniorLivingReferral['source'], string> = {
  family: 'Family',
  physician: 'Physician',
  hospital: 'Hospital',
  community: 'Community',
  web: 'Web',
};

// Fallback shown until the tenant has live /cl/referral-sources records.
export const SENIOR_LIVING_REFERRALS_FIXTURE: readonly SeniorLivingReferral[] = [
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
