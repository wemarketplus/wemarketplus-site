import { Card, CardContent } from '@/shared/ui/core';
import { HOW_IT_WORKS } from '../../constants/landingContent';

// index.html #workflow — "Live in Under 30 Minutes", 4 steps.
export function HowItWorks() {
  return (
    <section id="workflow" className="border-y border-white/[0.06] bg-white/[0.015]">
      <div className="mx-auto max-w-7xl px-6 py-20">
        <div className="mb-10 text-center">
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-sage">
            Get Started Fast
          </p>
          <h2 className="mt-3 font-serif-display text-3xl font-black text-foreground sm:text-4xl">
            Live in Under 30 Minutes
          </h2>
          <p className="mx-auto mt-3 max-w-xl text-sm text-muted">
            No IT department. No onboarding calls. No configuration. Subscribe and
            start closing admits today.
          </p>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {HOW_IT_WORKS.map((s) => (
            <Card key={s.num}>
              <CardContent className="space-y-2 px-5 py-6">
                <div className="font-serif-display text-3xl font-black text-sage">{s.num}</div>
                <h3 className="text-base font-bold text-foreground">{s.title}</h3>
                <p className="text-sm leading-relaxed text-muted">{s.body}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </section>
  );
}
