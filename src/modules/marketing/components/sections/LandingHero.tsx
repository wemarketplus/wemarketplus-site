import { Link } from 'react-router-dom';
import { Button } from '@/shared/ui/core';
import { HERO } from '../../constants/landingContent';

// index.html hero (#hospicelink) — sage radial glow, breathing eyebrow,
// the "next 5 admits" headline with an accent clause, three CTAs, proof points.
export function LandingHero() {
  return (
    <section id="hospicelink" className="relative overflow-hidden border-b border-white/[0.06]">
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 -z-10"
        style={{
          background:
            'radial-gradient(ellipse 600px 400px at 50% 0%, rgb(var(--color-sage) / 0.10), transparent 60%)',
        }}
      />
      <div className="mx-auto max-w-3xl px-6 py-24 text-center animate-slide-up">
        <span className="inline-flex items-center gap-2 rounded-pill border border-sage/22 bg-sage/10 px-3 py-1 text-[12px] font-semibold text-sage">
          <span className="h-1.5 w-1.5 animate-breathe rounded-full bg-sage" />
          {HERO.eyebrow}
        </span>
        <h1 className="mt-5 font-serif-display text-[clamp(36px,6.5vw,64px)] font-black leading-[1.05] text-foreground">
          {HERO.title}{' '}
          <span className="italic text-sage">{HERO.titleAccent}</span>
        </h1>
        <p className="mx-auto mt-5 max-w-xl text-base leading-relaxed text-muted">
          {HERO.subheading}
        </p>
        <div className="mt-8 flex flex-wrap justify-center gap-3">
          <Link to="/pricing">
            <Button size="lg" className="bg-sage text-[#06080e]">
              View Plans &amp; Pricing
            </Button>
          </Link>
          <Link to="/demo/hospicelink/pro">
            <Button size="lg" variant="outline">Try Interactive Demo</Button>
          </Link>
          <Link to="/login">
            <Button size="lg" variant="outline">Log In to CRM</Button>
          </Link>
        </div>
        <div className="mt-8 flex flex-wrap justify-center gap-x-6 gap-y-2 text-[12px] text-muted-soft">
          {HERO.proofPoints.map((p) => (
            <span key={p} className="inline-flex items-center gap-1.5">
              <span className="text-sage">✓</span> {p}
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}
