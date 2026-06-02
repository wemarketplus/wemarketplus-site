import { Link } from 'react-router-dom';
import { cn } from '@/shared/utils/cn';
import type { PlanTone, PricingPlan } from '../constants/hospicePricingPlans';

// index.html .plan-card — gradient plan card with a tier-badge, Instrument
// Serif name, feature list, and per-user-band tier rows, each with a tinted
// Subscribe button. Featured = sage gradient, premium = amber gradient.
const CARD_VARIANT: Record<PricingPlan['variant'], string> = {
  default:
    'border-white/[0.08] bg-[linear-gradient(160deg,rgba(255,255,255,0.035),rgba(255,255,255,0.01))]',
  featured:
    'border-sage/[0.22] bg-[linear-gradient(160deg,rgba(79,200,122,0.055),rgba(79,200,122,0.01))]',
  premium:
    'border-amber/[0.22] bg-[linear-gradient(160deg,rgba(201,144,58,0.07),rgba(201,144,58,0.015))]',
};

const BADGE_TONE: Record<PlanTone, string> = {
  azure: 'border-azure/[0.22] bg-azure/10 text-azure',
  sage: 'border-sage/[0.22] bg-sage/10 text-sage',
  amber: 'border-amber/[0.22] bg-amber/10 text-amber',
};

const BTN_TONE: Record<PlanTone, string> = {
  azure: 'bg-azure',
  sage: 'bg-sage',
  amber: 'bg-amber',
};

export function PlanCard({ plan }: { plan: PricingPlan }) {
  return (
    <div
      className={cn(
        'relative rounded-[22px] border p-[30px]',
        CARD_VARIANT[plan.variant],
      )}
    >
      {plan.variant === 'featured' ? (
        <div className="absolute -top-[13px] left-1/2 -translate-x-1/2 whitespace-nowrap rounded-pill bg-sage px-4 py-1 text-[11px] font-extrabold tracking-[0.04em] text-[#06080e]">
          Best Value
        </div>
      ) : null}
      <div
        className={cn(
          'mb-3 inline-block rounded-pill border px-[11px] py-[3px] text-[10px] font-bold uppercase tracking-[0.07em]',
          BADGE_TONE[plan.tone],
        )}
      >
        {plan.badge}
      </div>
      <div
        className={cn(
          'mb-1 font-serif-display text-[24px] tracking-[-0.01em]',
          plan.variant === 'premium' ? 'text-amber' : 'text-foreground',
        )}
      >
        {plan.name}
      </div>
      {plan.startingAt ? (
        <div className="mb-1 text-[11px] font-bold uppercase tracking-[0.06em] text-amber">
          {plan.startingAt}
        </div>
      ) : null}
      <div className="mb-4 text-[12px] text-faint">{plan.tagline}</div>
      <div className="mb-[18px] rounded-[12px] bg-white/[0.025] p-3.5 text-[13px] leading-[1.66] text-muted">
        {plan.blurb}
      </div>
      <ul className="mb-[22px] flex flex-col gap-2">
        {plan.features.map((f) => (
          <li key={f} className="flex items-start gap-2.5 text-[13px] leading-[1.5] text-[#bfcede]">
            <span className="mt-px flex h-[17px] w-[17px] flex-shrink-0 items-center justify-center rounded-full border border-sage/[0.22] bg-sage/10">
              <svg
                viewBox="0 0 24 24"
                className="h-2 w-2"
                fill="none"
                stroke="rgb(var(--color-sage))"
                strokeWidth={2.5}
              >
                <polyline points="20 6 9 17 4 12" />
              </svg>
            </span>
            {f}
          </li>
        ))}
      </ul>
      <div className="mb-4 flex flex-col gap-2">
        {plan.rows.map((r) => (
          <div
            key={r.users}
            className="flex items-center justify-between gap-2.5 rounded-[10px] border border-white/[0.08] bg-white/[0.03] px-3.5 py-2.5 transition-colors hover:border-white/[0.18]"
          >
            <div className="flex flex-col gap-0.5">
              <span className="text-[12px] font-semibold text-faint">{r.users}</span>
              <span className="text-[20px] font-black leading-none tracking-[-0.02em] text-foreground">
                {r.price}
                <span className="text-[12px] font-medium text-faint">/mo</span>
              </span>
            </div>
            <Link
              to="/onboarding"
              className={cn(
                'whitespace-nowrap rounded-pill px-5 py-2 text-[12px] font-extrabold text-[#06080e] transition-opacity hover:opacity-85',
                BTN_TONE[plan.tone],
              )}
            >
              Subscribe
            </Link>
          </div>
        ))}
      </div>
      <Link
        to={plan.demoHref}
        className="block rounded-pill border border-white/[0.14] py-[11px] text-center text-[13px] font-semibold text-muted transition-colors hover:border-white/[0.28] hover:text-foreground"
      >
        {plan.demoLabel}
      </Link>
    </div>
  );
}
