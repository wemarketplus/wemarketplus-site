import { MarketingShell } from '../components/MarketingShell';
import { JumpToBar } from '../components/JumpToBar';
import { PricingHeader } from '../components/PricingHeader';
import { LandingHero } from '../components/sections/LandingHero';
import { MetricsStrip } from '../components/sections/MetricsStrip';
import { PlatformPreview } from '../components/sections/PlatformPreview';
import { FeatureCards } from '../components/sections/FeatureCards';
import { OriginStory } from '../components/sections/OriginStory';
import { HowItWorks } from '../components/sections/HowItWorks';
import { VsGeneric } from '../components/sections/VsGeneric';
import { Testimonials } from '../components/sections/Testimonials';
import { PricingCards } from '../components/sections/PricingCards';
import { ComparisonTable } from '../components/sections/ComparisonTable';
import { SocialProof } from '../components/sections/SocialProof';
import { CommunityOverview } from '../components/sections/CommunityOverview';
import { SecurityGrid } from '../components/sections/SecurityGrid';
import { BaaNote } from '../components/sections/BaaNote';
import { FaqAccordion } from '../components/sections/FaqAccordion';
import { ContactSection } from '../components/sections/ContactSection';
import { FinalCta } from '../components/sections/FinalCta';

// Full landing page — sections in the same order as
// wemarketplus-site/index.html: hero → metrics → preview → features → origin →
// workflow → vs-generic → testimonials → pricing (+ full comparison) → social
// proof → communitylink → security → baa → faq → final CTA → contact.
export function LandingPage() {
  return (
    <MarketingShell>
      <JumpToBar />
      <LandingHero />
      <MetricsStrip />
      <PlatformPreview />
      <FeatureCards />
      <OriginStory />
      <HowItWorks />
      <VsGeneric />
      <Testimonials />

      {/* #pricing — HospiceLink plans */}
      <section id="pricing" className="mx-auto max-w-[1200px] px-7 pt-[72px]">
        <PricingHeader />
      </section>
      <PricingCards />
      <ComparisonTable />

      <SocialProof />
      <CommunityOverview />
      <SecurityGrid />
      <BaaNote />
      <FaqAccordion />
      <FinalCta />
      <ContactSection />
    </MarketingShell>
  );
}
