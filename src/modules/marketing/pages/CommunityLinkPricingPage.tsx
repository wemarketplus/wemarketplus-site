import { MarketingShell } from '../components/MarketingShell';
import { CommunityPlanCard } from '../components/CommunityPlanCard';
import { SectionHeading } from '../components/SectionHeading';
import { COMMUNITYLINK_PLANS } from '../constants/communityPricingPlans';

export function CommunityLinkPricingPage() {
  return (
    <MarketingShell>
      <section
        id="cl-pricing"
        data-product="communitylink"
        className="mx-auto max-w-[1100px] px-7 pt-[72px]"
      >
        <SectionHeading
          kicker="CommunityLink Pricing"
          tone="amber"
          title="Plans for Every Community"
          body="Per facility pricing. No hidden fees. Cancel anytime."
        />
        <div className="grid grid-cols-1 gap-[18px] pt-2 md:grid-cols-3">
          {COMMUNITYLINK_PLANS.map((plan) => (
            <CommunityPlanCard key={plan.eyebrow} plan={plan} />
          ))}
        </div>
      </section>
    </MarketingShell>
  );
}
