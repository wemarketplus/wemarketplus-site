import type { Product, Tier } from '@/shared/types';

// Marketing module owns every pre-auth public surface that isn't part of
// the auth funnel itself (login/reset/etc live in `modules/auth`).

export interface MarketingTierCard {
  tier: Tier;
  product: Product;
  name: string;
  tagline: string;
  monthlyPrice: number;
  perSeat: boolean;
  // User-band note shown under the price (e.g. "0–5 users · scales to …").
  bands?: string;
  highlights: readonly string[];
  featured?: boolean;
}

export interface MarketingFeature {
  title: string;
  description: string;
}

export interface MarketingUiState {
  _placeholder: true;
}
