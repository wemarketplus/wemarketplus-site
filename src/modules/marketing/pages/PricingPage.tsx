import { MarketingShell } from '../components/MarketingShell';
import { PlanCard } from '../components/PlanCard';
import { PricingHeader } from '../components/PricingHeader';
import { ComparisonTable } from '../components/sections/ComparisonTable';
import { HOSPICELINK_PLANS } from '../constants/hospicePricingPlans';

export function PricingPage() {
  return (
    <MarketingShell>
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
    </MarketingShell>
  );
}
