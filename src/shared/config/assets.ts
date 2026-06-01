// Brand image assets copied verbatim from wemarketplus-site/assets/ into
// public/assets/. Reference these constants instead of hardcoding paths so
// there's one place to update if a logo is re-exported.
//
// These are the raster product logos the marketing site ships. The auth/CRM
// chrome uses the text wordmark (<Logo/>); these are for marketing surfaces,
// OG/social previews, and anywhere a full logo lockup is wanted.
export const BRAND_ASSETS = {
  siteLogo: '/assets/site-logo.png',
  proLogo: '/assets/pro-logo.png',
  goldLogo: '/assets/gold-logo.jpeg',
  maxLogo: '/assets/max-logo.png',
} as const;

import { Tier } from '@/shared/types';

// Maps a tier to its product logo lockup.
export const TIER_LOGO: Record<Tier, string> = {
  [Tier.Pro]: BRAND_ASSETS.proLogo,
  [Tier.Gold]: BRAND_ASSETS.goldLogo,
  [Tier.Max]: BRAND_ASSETS.maxLogo,
};
