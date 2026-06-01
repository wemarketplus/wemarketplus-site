// Senior-living referral sources are a different domain from hospice
// referrals (different fields, different relationship cadence), so this
// module owns its own types even though some shape names overlap.
export interface SeniorLivingReferral {
  id: string;
  name: string;
  organization: string;
  email: string;
  phone: string;
  source: 'family' | 'physician' | 'hospital' | 'community' | 'web';
  rating: 1 | 2 | 3 | 4 | 5;
  notes?: string;
}

export interface ClReferralsUiState {
  _placeholder: true;
}
