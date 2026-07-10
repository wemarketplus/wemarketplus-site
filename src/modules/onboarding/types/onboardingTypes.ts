import type { Product, Tier } from '@/shared/types';

// Onboarding wizard state — mirrors wemarketplus-site/onboard.html.
// 4-step funnel: Account → Agency → BAA → Launch.

export type OnboardingStep = 'account' | 'agency' | 'baa' | 'launch';

export interface AccountInfo {
  firstName: string;
  lastName: string;
  email: string;
  password: string;
}

export interface AgencyInfo {
  agencyName: string;
  city: string;
  state: string;
  phone: string;
  marketerCount: number;
  product?: Product;
  tier?: Tier;
}

export interface BAASignature {
  signature: string;
  title: string;
  acknowledged: boolean;
}

export interface OnboardingDraft {
  account: Partial<AccountInfo>;
  agency: Partial<AgencyInfo>;
  baa: Partial<BAASignature>;
  // Stripe session id from billing flow (TODO: when checkout is wired)
  stripeSessionId?: string;
}

export interface OnboardingState {
  currentStep: OnboardingStep;
  draft: OnboardingDraft;
  // Epoch milliseconds at which the draft expires from localStorage.
  draftExpiresAt: number | null;
  completed: boolean;
  // Set when register returned requiresEmailVerification (production) — the
  // launch step shows "check your email" for this address instead of the
  // logged-in checklist.
  pendingVerificationEmail: string | null;
}

// POST /auth/onboard payload — sent on step 3 (BAA) per the site's flow.
export interface OnboardRequest {
  account: AccountInfo;
  agency: AgencyInfo;
  baa: BAASignature;
  stripeSessionId?: string;
}
