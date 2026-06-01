import { Product } from '@/shared/types';
import {
  COMMUNITYLINK_FEATURES,
} from '../constants/marketingConstants';
import { MarketingShell } from '../components/MarketingShell';
import { Hero } from '../components/Hero';
import { FeatureGrid } from '../components/FeatureGrid';
import { PricingGrid } from '../components/PricingGrid';
import { useMarketingTiers } from '../hooks/useMarketingTiers';

export function CommunityLinkLandingPage() {
  const tiers = useMarketingTiers(Product.CommunityLink);
  return (
    <MarketingShell>
      <Hero
        eyebrow="CommunityLink"
        title={<>Operations & sales for<br />senior-living communities.</>}
        description="Leads, tours, apartments, make-ready, maintenance, and revenue — in one workspace built for community teams."
        primaryCta={{ label: 'Start free', to: '/onboarding' }}
        secondaryCta={{ label: 'Watch demo', to: '/demo/communitylink/pro' }}
      />
      <FeatureGrid features={COMMUNITYLINK_FEATURES} />
      <section className="mx-auto max-w-7xl px-6 pb-12">
        <div className="space-y-1 text-center">
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-soft">
            CommunityLink pricing
          </p>
          <h2 className="font-serif-display text-3xl text-foreground">
            Per-community pricing
          </h2>
        </div>
      </section>
      <PricingGrid tiers={tiers} />
    </MarketingShell>
  );
}
