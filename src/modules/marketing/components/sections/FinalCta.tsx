import { ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Button } from '@/shared/ui/core';

// index.html final CTA panel.
export function FinalCta() {
  return (
    <section className="relative overflow-hidden">
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 -z-10"
        style={{
          background:
            'radial-gradient(ellipse 800px 400px at 50% 100%, rgb(var(--color-sage) / 0.10), transparent 65%)',
        }}
      />
      <div className="mx-auto max-w-3xl px-6 py-24 text-center">
        <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-sage">
          Founders Pricing Ends June 1
        </p>
        <h2 className="mt-4 font-serif-display text-4xl font-black leading-tight text-foreground sm:text-5xl">
          Your First 5 New Referrals in 7 Days or Less
        </h2>
        <p className="mx-auto mt-4 max-w-xl text-base text-muted">
          Stop losing leads to spreadsheets. Start closing more admits this week. No
          setup fee, live in 30 minutes.
        </p>
        <div className="mt-8 flex flex-wrap justify-center gap-3">
          <Link to="/pricing">
            <Button size="lg">
              View Plans &amp; Pricing <ArrowRight className="h-4 w-4" />
            </Button>
          </Link>
          <Link to="/login">
            <Button size="lg" variant="outline">Log In to CRM</Button>
          </Link>
        </div>
        <p className="mt-5 text-[11px] uppercase tracking-[0.1em] text-muted-soft">
          No setup fee · Cancel anytime · HIPAA-Ready · 30-day guarantee
        </p>
      </div>
    </section>
  );
}
