import { Product } from '@/shared/types';
import { MarketingShell } from '../components/MarketingShell';
import { PricingGrid } from '../components/PricingGrid';
import { useMarketingTiers } from '../hooks/useMarketingTiers';

export function CommunityLinkPricingPage() {
  const tiers = useMarketingTiers(Product.CommunityLink);
  return (
    <MarketingShell>
      <section className="mx-auto max-w-3xl px-6 pt-16 text-center">
        <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-soft">
          CommunityLink pricing
        </p>
        <h1 className="mt-3 font-serif-display text-4xl text-foreground">
          Pricing per community
        </h1>
        <p className="mx-auto mt-3 max-w-xl text-sm text-muted">
          Unlimited users included. Scale across your portfolio with volume
          pricing — talk to us for 5+ communities.
        </p>
      </section>
      <PricingGrid tiers={tiers} />
    </MarketingShell>
  );
}
