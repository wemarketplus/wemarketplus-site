import { Link } from 'react-router-dom';

// index.html final CTA — a contained sage→azure gradient .cta-panel.
export function FinalCta() {
  return (
    <section className="mx-auto max-w-[1140px] px-7 py-16">
      <div className="rounded-[22px] border border-sage/[0.12] bg-[linear-gradient(135deg,rgba(79,200,122,0.05),rgba(61,158,232,0.04))] px-6 py-10 text-center sm:px-11 sm:py-[60px]">
        <div className="mb-[22px] inline-block rounded-pill border border-amber/[0.22] bg-amber/10 px-3.5 py-1 text-[11px] font-bold uppercase tracking-[0.08em] text-amber">
          Founders Pricing Ends June 1
        </div>
        <h2 className="mb-4 font-serif-display text-[clamp(30px,5vw,56px)] leading-[1.06] tracking-[-0.02em] text-foreground">
          Your First 5 New Referrals
          <br />
          <em className="italic text-sage">in 7 Days or Less</em>
        </h2>
        <p className="mx-auto mb-[34px] max-w-[460px] text-[15px] leading-[1.72] text-muted">
          Stop losing leads to spreadsheets. Start closing more admits this week.
          No setup fee, live in 30 minutes.
        </p>
        <div className="mb-[18px] flex flex-wrap justify-center gap-3.5">
          <Link
            to="/#pricing"
            className="rounded-pill bg-sage px-8 py-[15px] text-[15px] font-bold text-[#06080e] transition-opacity hover:opacity-[0.88]"
          >
            View Plans &amp; Pricing
          </Link>
          <Link
            to="/login"
            className="rounded-pill border border-white/[0.14] px-[30px] py-[15px] text-[14px] font-semibold text-foreground transition-colors hover:border-white/[0.28] hover:bg-white/[0.05]"
          >
            Log In to CRM
          </Link>
        </div>
        <p className="mt-4 text-[12px] text-faint">
          No setup fee — Cancel anytime — HIPAA-Ready — 30-day guarantee
        </p>
      </div>
    </section>
  );
}
