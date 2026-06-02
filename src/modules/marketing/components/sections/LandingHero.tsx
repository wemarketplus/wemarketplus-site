import { Link } from 'react-router-dom';
import { Button } from '@/shared/ui/core';
import { HERO } from '../../constants/landingContent';

// index.html hero (#hospicelink) — sage radial glow, breathing eyebrow,
// the "next 5 admits" headline with an accent clause, three CTAs, proof points.
export function LandingHero() {
  return (
    <section id="hospicelink" className="relative overflow-hidden border-b border-white/[0.06]">
      {/* Subtle sage radial from the top — flat, no glow shadows. */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 -z-10"
        style={{
          background:
            'radial-gradient(ellipse 600px 400px at 50% 0%, rgb(var(--color-sage) / 0.06), transparent 70%)',
        }}
      />
      <div className="mx-auto max-w-[1200px] px-7 pb-[72px] pt-24 text-center">
        <span
          className="inline-flex animate-reveal items-center gap-2 rounded-pill border border-sage/[0.22] bg-sage/10 px-3.5 py-[5px] text-[11px] font-bold uppercase tracking-[0.06em] text-sage motion-reduce:animate-none"
        >
          <span className="h-1.5 w-1.5 animate-breathe rounded-full bg-sage motion-reduce:animate-none" />
          {HERO.eyebrow}
        </span>
        <h1
          className="whitespace-pre-line mx-auto mt-[30px] animate-reveal font-serif-display text-[clamp(44px,6.5vw,80px)] font-normal leading-[1.02] tracking-[-0.02em] text-foreground motion-reduce:animate-none [animation-delay:90ms]"
        >
          {HERO.title}{' '}
          <span className="block italic text-sage">{HERO.titleAccent}</span>
        </h1>
        <p
          className="mx-auto mt-[22px] max-w-[540px] animate-reveal text-[clamp(15px,1.8vw,18px)] font-normal leading-[1.78] text-muted motion-reduce:animate-none [animation-delay:180ms]"
        >
          The only CRM built{' '}
          <em className="font-semibold not-italic text-foreground">exclusively</em>{' '}
          for hospice marketers. Every referral tracked, every follow-up
          automated, every admit captured — live in 30 minutes, HIPAA-ready from
          day one.
        </p>
        <div
          className="mt-[38px] flex animate-reveal flex-wrap justify-center gap-3 motion-reduce:animate-none [animation-delay:270ms]"
        >
          <Link to="/#pricing">
            <Button
              size="lg"
              className="!h-auto !px-7 !py-[14px] !text-[14px] !font-bold bg-sage text-[#06080e] transition-all duration-300 hover:-translate-y-0.5"
            >
              View Plans &amp; Pricing
            </Button>
          </Link>
          <Link to="/demo/hospicelink/pro">
            <Button
              size="lg"
              variant="outline"
              className="!h-auto !px-7 !py-[14px] !text-[14px] !font-semibold transition-all duration-300 hover:-translate-y-0.5"
            >
              Try Interactive Demo
            </Button>
          </Link>
          <Link to="/login">
            <Button
              size="lg"
              variant="outline"
              className="!h-auto !px-7 !py-[14px] !text-[14px] !font-semibold transition-all duration-300 hover:-translate-y-0.5"
            >
              Log In to CRM
            </Button>
          </Link>
        </div>
        <div
          className="mt-9 flex animate-reveal flex-wrap items-center justify-center gap-6 motion-reduce:animate-none [animation-delay:360ms]"
        >
          {HERO.proofPoints.map((p) => (
            <span
              key={p}
              className="inline-flex items-center gap-[7px] text-[12px] font-semibold text-faint"
            >
              <span className="flex h-[18px] w-[18px] flex-shrink-0 items-center justify-center rounded-full border border-sage/[0.22] bg-sage/10">
                <svg
                  viewBox="0 0 24 24"
                  className="h-[9px] w-[9px]"
                  fill="none"
                  stroke="rgb(var(--color-sage))"
                  strokeWidth={2.5}
                >
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              </span>
              {p}
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}
