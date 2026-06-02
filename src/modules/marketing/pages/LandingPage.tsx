import { MarketingShell } from '../components/MarketingShell';
import { JumpToBar } from '../components/JumpToBar';
import { PlanCard } from '../components/PlanCard';
import { PricingHeader } from '../components/PricingHeader';
import { HOSPICELINK_PLANS } from '../constants/hospicePricingPlans';
import { LandingHero } from '../components/sections/LandingHero';
import { MetricsStrip } from '../components/sections/MetricsStrip';
import { PlatformPreview } from '../components/sections/PlatformPreview';
import { FeatureCards } from '../components/sections/FeatureCards';
import { OriginStory } from '../components/sections/OriginStory';
import { HowItWorks } from '../components/sections/HowItWorks';
import { VsGeneric } from '../components/sections/VsGeneric';
import { Testimonials } from '../components/sections/Testimonials';
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
      <section className="mx-auto max-w-[1100px] px-7 pb-12 pt-[38px]">
        <div className="grid grid-cols-[repeat(auto-fit,minmax(300px,1fr))] gap-[18px]">
          {HOSPICELINK_PLANS.map((plan) => (
            <PlanCard key={plan.name} plan={plan} />
          ))}
        </div>
      </section>
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
