import { ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Button } from '@/shared/ui/core';

interface HeroProps {
  eyebrow: string;
  title: React.ReactNode;
  description: React.ReactNode;
  primaryCta: { label: string; to: string };
  secondaryCta?: { label: string; to: string };
}

export function Hero({
  eyebrow,
  title,
  description,
  primaryCta,
  secondaryCta,
}: HeroProps) {
  return (
    <section className="relative overflow-hidden border-b border-white/[0.06]">
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 -z-10"
        style={{
          background:
            'radial-gradient(ellipse 900px 500px at 50% 0%, rgb(var(--color-primary) / 0.10), transparent 65%)',
        }}
      />
      <div className="mx-auto max-w-3xl px-6 py-24 text-center animate-slide-up">
        <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-soft">
          {eyebrow}
        </p>
        <h1 className="mt-4 font-serif-display text-5xl leading-tight text-foreground sm:text-6xl">
          {title}
        </h1>
        <p className="mx-auto mt-5 max-w-xl text-base text-muted">{description}</p>
        <div className="mt-8 flex flex-wrap justify-center gap-3">
          <Link to={primaryCta.to}>
            <Button size="lg">
              {primaryCta.label} <ArrowRight className="h-4 w-4" />
            </Button>
          </Link>
          {secondaryCta && (
            <Link to={secondaryCta.to}>
              <Button size="lg" variant="secondary">
                {secondaryCta.label}
              </Button>
            </Link>
          )}
        </div>
      </div>
    </section>
  );
}
