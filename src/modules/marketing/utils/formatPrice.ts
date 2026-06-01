import type { MarketingTierCard } from '../types/marketingTypes';

export function formatTierPrice(card: MarketingTierCard): string {
  return `$${card.monthlyPrice}${card.perSeat ? '/seat/mo' : '/mo'}`;
}
