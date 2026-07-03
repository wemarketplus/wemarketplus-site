import { Link } from 'react-router-dom';
import { Activity, MousePointer2, Star, type LucideIcon } from 'lucide-react';
import { setPendingPlan } from '@/modules/onboarding';
import { cn } from '@/shared/utils/cn';
import type { PlanTone } from '../constants/hospicePricingPlans';
import type {
  CommunityPlan,
  CommunityPlanIcon,
} from '../constants/communityPricingPlans';

// index.html CommunityLink pricing card — icon tile + per-facility price, a
// bordered seat-cap box, a feature checklist, a "Get Started" CTA, and a demo
// link. The popular (Gold) card gets a 2px amber border and a MOST POPULAR
// ribbon.
const ACCENT: Record<PlanTone, { text: string; check: string; btn: string; tile: string }> = {
  azure: { text: 'text-azure', check: 'text-azure', btn: 'bg-azure', tile: 'bg-azure/15 text-azure' },
  amber: { text: 'text-amber', check: 'text-amber', btn: 'bg-amber', tile: 'bg-amber/15 text-amber' },
  sage: { text: 'text-sage', check: 'text-sage', btn: 'bg-sage', tile: 'bg-sage/15 text-sage' },
};

const ICON: Record<CommunityPlanIcon, LucideIcon> = {
  activity: Activity,
  star: Star,
  pointer: MousePointer2,
};

export function CommunityPlanCard({ plan }: { plan: CommunityPlan }) {
  const a = ACCENT[plan.tone];
  const Icon = ICON[plan.icon];
  return (
    <div
      className={cn(
        // flex-col + h-full → every card fills its equal-height grid row and
        // pins the CTA block to the bottom regardless of feature count.
        'relative flex h-full flex-col rounded-[20px] bg-[#0a1628] p-7',
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
      <div className="mb-4 flex items-center gap-3">
        <span
          className={cn(
            'flex h-[38px] w-[38px] items-center justify-center rounded-[9px]',
            a.tile,
          )}
        >
          <Icon className="h-[19px] w-[19px]" strokeWidth={1.8} />
        </span>
        <div>
          <div className={cn('text-[12px] font-bold uppercase tracking-[0.08em]', a.text)}>
            {plan.eyebrow}
          </div>
          <div className="text-[13px] text-faint">{plan.subtitle}</div>
        </div>
      </div>
      <div className="flex items-end gap-1">
        <span className="text-[40px] font-black leading-none tracking-[-0.02em] text-foreground">
          {plan.price}
        </span>
        <span className="mb-1 text-[13px] text-faint">/month per facility</span>
      </div>
      <div className="mb-5 mt-4 rounded-[10px] border border-white/[0.08] bg-white/[0.02] px-3.5 py-2.5 text-[12px] font-semibold text-muted">
        {plan.users}
      </div>
      <ul className="mb-6 flex flex-col gap-2.5">
        {plan.features.map((f) => (
          <li key={f} className="flex items-start gap-2.5 text-[13px] leading-[1.5] text-[#bfcede]">
            <span className={cn('mt-px font-bold', a.check)}>✓</span>
            {f}
          </li>
        ))}
      </ul>
      <Link
        to={`/onboarding?plan=${plan.planKey}`}
        onClick={() => setPendingPlan(plan.planKey)}
        className={cn(
          'mt-auto block rounded-pill py-3 text-center text-[14px] font-extrabold text-[#06080e] transition-opacity hover:opacity-[0.88]',
          a.btn,
        )}
      >
        Get Started — {plan.price}/mo
      </Link>
      <Link
        to={plan.demoHref}
        className={cn('mt-3 block text-center text-[13px] font-semibold transition-opacity hover:opacity-80', a.text)}
      >
        {plan.demoLabel} →
      </Link>
    </div>
  );
}
