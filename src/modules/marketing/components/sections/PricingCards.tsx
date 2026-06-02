import { useScrollReveal } from '@/shared/hooks';
import { cn } from '@/shared/utils/cn';
import { revealClass, staggerStyle } from '@/shared/utils/scrollReveal';
import { PlanCard } from '../PlanCard';
import { HOSPICELINK_PLANS } from '../../constants/hospicePricingPlans';

// index.html #pricing plan grid — HospiceLink Pro / Max / Gold cards. Extracted
// from LandingPage so the page stays composition-only and the cards can reveal
// + stagger as they scroll into view. Each PlanCard keeps its own internal
// hover; the wrapper owns only the entrance animation.
export function PricingCards() {
  const { ref, visible } = useScrollReveal<HTMLElement>();

  return (
    <section ref={ref} className="mx-auto max-w-[1200px] px-7 pb-12 pt-[38px]">
      {/* auto-rows-fr → all plan cards share one row height; h-full carries that
          equal height through the reveal wrapper down to each PlanCard, so Pro,
          Max and Gold render at the same height regardless of feature/row count. */}
      <div className="grid auto-rows-fr grid-cols-[repeat(auto-fit,minmax(300px,1fr))] gap-[18px]">
        {HOSPICELINK_PLANS.map((plan, i) => (
          <div key={plan.name} className={cn('h-full', revealClass(visible))} style={staggerStyle(i, visible)}>
            <PlanCard plan={plan} />
          </div>
        ))}
      </div>
    </section>
  );
}
