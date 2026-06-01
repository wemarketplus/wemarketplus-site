import { Product } from '@/shared/types';
import { MarketingShell } from '../components/MarketingShell';
import { JumpToBar } from '../components/JumpToBar';
import { PricingGrid } from '../components/PricingGrid';
import { LandingHero } from '../components/sections/LandingHero';
import { MetricsStrip } from '../components/sections/MetricsStrip';
import { PlatformPreview } from '../components/sections/PlatformPreview';
import { FeatureCards } from '../components/sections/FeatureCards';
import { OriginStory } from '../components/sections/OriginStory';
import { HowItWorks } from '../components/sections/HowItWorks';
import { Testimonials } from '../components/sections/Testimonials';
import { ComparisonTable } from '../components/sections/ComparisonTable';
import { TrustBadges } from '../components/sections/TrustBadges';
import { CommunityOverview } from '../components/sections/CommunityOverview';
import { SecurityGrid } from '../components/sections/SecurityGrid';
import { FaqAccordion } from '../components/sections/FaqAccordion';
import { ContactSection } from '../components/sections/ContactSection';
import { FinalCta } from '../components/sections/FinalCta';
import { useMarketingTiers } from '../hooks/useMarketingTiers';

// Full landing page — sections in the same order as
// wemarketplus-site/index.html (verified against the live-site screenshots).
export function LandingPage() {
  const hospiceTiers = useMarketingTiers(Product.HospiceLink);

  return (
    <MarketingShell>
      <JumpToBar />
      <LandingHero />
      <MetricsStrip />
      <PlatformPreview />
      <FeatureCards />
      <OriginStory />
      <HowItWorks />
      <Testimonials />

      {/* #pricing — HospiceLink plans */}
      <section id="pricing" className="mx-auto max-w-7xl px-6 pt-20">
        <div className="text-center">
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-sage">
            🕐 Founders Pricing — Ends May 31, 2026
          </p>
          <h2 className="mt-3 font-serif-display text-3xl text-foreground sm:text-4xl">
            Simple, Transparent Pricing
          </h2>
          <p className="mx-auto mt-3 max-w-2xl text-sm text-muted">
            All plans include HIPAA-ready setup, BAA at checkout, self-guided
            onboarding, and the 30-day money-back guarantee.
          </p>
        </div>
      </section>
      <PricingGrid tiers={hospiceTiers} />
      <ComparisonTable />

      <TrustBadges />
      <CommunityOverview />
      <SecurityGrid />
      <FaqAccordion />
      <ContactSection />
      <FinalCta />
    </MarketingShell>
  );
}
