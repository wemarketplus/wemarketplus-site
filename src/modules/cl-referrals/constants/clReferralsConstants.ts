import type { SeniorLivingReferral } from '../types/clReferralsTypes';

export const SOURCE_LABEL: Record<SeniorLivingReferral['source'], string> = {
  family: 'Family',
  physician: 'Physician',
  hospital: 'Hospital',
  community: 'Community',
  web: 'Web',
};
