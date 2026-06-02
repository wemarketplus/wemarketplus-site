import { ShieldCheck } from 'lucide-react';

// index.html #pricing .section-header — amber kicker pill, serif title, a red
// "price increases / EXPIRED" countdown chip, the body line, and a sage 30-day
// guarantee chip.
export function PricingHeader() {
  return (
    <div className="mb-[52px] text-center">
      <div className="mb-[14px] inline-block rounded-pill border border-amber/[0.22] bg-amber/10 px-[13px] py-1 text-[11px] font-bold uppercase tracking-[0.09em] text-amber">
        ⏰ Founders Pricing — Ends May 31, 2026
      </div>
      <h2 className="mb-3 font-serif-display text-[clamp(28px,4vw,48px)] font-normal leading-[1.08] tracking-[-0.02em] text-foreground">
        Simple, Transparent Pricing
      </h2>
      <div className="mb-1 mt-3.5 flex justify-center">
        <div className="inline-flex items-center gap-2 rounded-pill border border-[#ef4444]/20 bg-[#ef4444]/[0.08] px-4 py-1.5">
          <span className="h-1.5 w-1.5 animate-breathe rounded-full bg-[#ef4444]" />
          <span className="text-[12px] font-bold text-[#fca5a5]">
            Price increases June 1, 2026 —
          </span>
          <span className="font-mono text-[12px] font-extrabold tracking-[0.02em] text-[#ef4444]">
            EXPIRED
          </span>
        </div>
      </div>
      <p className="mx-auto max-w-[500px] text-[15px] leading-[1.75] text-muted">
        All plans include HIPAA-ready setup, BAA at checkout, self-guided
        onboarding, and the 30-day money-back guarantee.
      </p>
      <div className="mt-4 inline-flex items-center gap-2 rounded-pill border border-sage/[0.22] bg-sage/10 px-4 py-[7px] text-[13px] font-semibold text-sage">
        <ShieldCheck className="h-3.5 w-3.5" />
        30-Day Money-Back Guarantee — No Questions Asked
      </div>
    </div>
  );
}
