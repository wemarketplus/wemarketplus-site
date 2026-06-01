import type { MarketingTierCard } from '../types/marketingTypes';
import { TierCard } from './TierCard';

export function PricingGrid({ tiers }: { tiers: readonly MarketingTierCard[] }) {
  return (
    <section className="mx-auto max-w-7xl px-6 py-12">
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {tiers.map((t) => (
          <TierCard key={`${t.product}-${t.tier}`} card={t} />
        ))}
      </div>
    </section>
  );
}
