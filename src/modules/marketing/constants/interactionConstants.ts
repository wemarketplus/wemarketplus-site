// Hover/interaction class tokens for marketing landing sections. Kept here
// (not inline in components) per the module's constants rule. Static only.

import type { CommunityPillar, TrustBadge } from '../types/landingTypes';

// Icon accent colour per trust-badge tone (see TrustBadgePill). Static string
// map — the icon component map itself stays with the component.
export const TRUST_BADGE_ICON_TONE: Record<TrustBadge['tone'], string> = {
  sage: 'text-sage',
  azure: 'text-azure',
  amber: 'text-amber',
};

// CommunityLink value-pillar card accents (see CommunityOverview). Border alpha
// matches the live wemarketplus.com cards (tone @ 15%).
export const PILLAR_BORDER: Record<CommunityPillar['tone'], string> = {
  amber: 'border-amber/15',
  sage: 'border-sage/15',
  azure: 'border-azure/15',
};

export const PILLAR_ICON_TILE: Record<CommunityPillar['tone'], string> = {
  amber: 'bg-amber/15 text-amber',
  sage: 'bg-sage/15 text-sage',
  azure: 'bg-azure/15 text-azure',
};

// Feature-card hover: a subtle lift + faint 1.02 scale and a neutral border
// brighten — no glow shadow. Transition lives on the card itself and is
// intentionally separate from the scroll-reveal animation (which runs on the
// parent wrapper) so the two never fight over `transform`. GPU-friendly
// (transform/border-color) and fully neutralised under prefers-reduced-motion.
export const FEATURE_CARD_HOVER =
  'transition-[transform,border-color] duration-300 ease-out will-change-transform ' +
  'hover:-translate-y-1 hover:scale-[1.02] hover:border-white/20 ' +
  'motion-reduce:transition-none motion-reduce:hover:translate-y-0 motion-reduce:hover:scale-100';
