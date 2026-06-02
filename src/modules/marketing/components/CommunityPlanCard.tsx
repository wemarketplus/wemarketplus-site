import { Link } from 'react-router-dom';
import { cn } from '@/shared/utils/cn';
import type { PlanTone } from '../constants/hospicePricingPlans';
import type { CommunityPlan } from '../constants/communityPricingPlans';

// index.html CommunityLink pricing card — single per-facility price, feature
// checklist, and a "Get Started" CTA. The popular (Gold) card gets a 2px amber
// border and a MOST POPULAR ribbon.
const ACCENT: Record<PlanTone, { text: string; check: string; btn: string }> = {
  azure: { text: 'text-azure', check: 'text-azure', btn: 'bg-azure' },
  amber: { text: 'text-amber', check: 'text-amber', btn: 'bg-amber' },
  sage: { text: 'text-sage', check: 'text-sage', btn: 'bg-sage' },
};

export function CommunityPlanCard({ plan }: { plan: CommunityPlan }) {
  const a = ACCENT[plan.tone];
  return (
    <div
      className={cn(
        'relative rounded-[20px] bg-[#0a1628] p-7',
        plan.popular
          ? 'border-2 border-amber/40'
          : 'border border-white/[0.08]',
      )}
    >
      {plan.popular ? (
        <div className="absolute -top-3 left-1/2 -translate-x-1/2 whitespace-nowrap rounded-pill bg-amber px-3.5 py-1 text-[11px] font-extrabold text-[#06080e]">
          MOST POPULAR
        </div>
      ) : null}
      <div className={cn('text-[12px] font-bold uppercase tracking-[0.08em]', a.text)}>
        {plan.eyebrow}
      </div>
      <div className="mb-3 mt-1 text-[13px] text-faint">{plan.subtitle}</div>
      <div className="flex items-end gap-1">
        <span className="text-[40px] font-black leading-none tracking-[-0.02em] text-foreground">
          {plan.price}
        </span>
        <span className="mb-1 text-[13px] text-faint">/month per facility</span>
      </div>
      <div className="mb-5 mt-1 text-[12px] font-semibold text-muted">{plan.users}</div>
      <ul className="mb-6 flex flex-col gap-2.5">
        {plan.features.map((f) => (
          <li key={f} className="flex items-start gap-2.5 text-[13px] leading-[1.5] text-[#bfcede]">
            <span className={cn('mt-px font-bold', a.check)}>✓</span>
            {f}
          </li>
        ))}
      </ul>
      <Link
        to="/onboarding"
        className={cn(
          'block rounded-pill py-3 text-center text-[14px] font-extrabold text-[#06080e] transition-opacity hover:opacity-[0.88]',
          a.btn,
        )}
      >
        Get Started — {plan.price}/mo
      </Link>
    </div>
  );
}
