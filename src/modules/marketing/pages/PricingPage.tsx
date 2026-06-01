import { Product } from '@/shared/types';
import { MarketingShell } from '../components/MarketingShell';
import { PricingGrid } from '../components/PricingGrid';
import { useMarketingTiers } from '../hooks/useMarketingTiers';

export function PricingPage() {
  const tiers = useMarketingTiers(Product.HospiceLink);
  return (
    <MarketingShell>
      <section className="mx-auto max-w-3xl px-6 pt-16 text-center">
        <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-soft">
          HospiceLink pricing
        </p>
        <h1 className="mt-3 font-serif-display text-4xl text-foreground">
          Simple, per-seat pricing
        </h1>
        <p className="mx-auto mt-3 max-w-xl text-sm text-muted">
          Start free, then pick the tier that matches your team. Switch any time —
          no contracts, no surprises.
        </p>
      </section>
      <PricingGrid tiers={tiers} />
    </MarketingShell>
  );
}
