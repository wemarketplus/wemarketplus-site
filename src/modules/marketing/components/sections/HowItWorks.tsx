import { Card, CardContent } from '@/shared/ui/core';
import { useScrollReveal } from '@/shared/hooks';
import { revealClass, staggerStyle } from '@/shared/utils/scrollReveal';
import { SectionHeading } from '../SectionHeading';
import { HOW_IT_WORKS } from '../../constants/landingContent';

// index.html #workflow — "Live in Under 30 Minutes", 4 steps with faint
// Instrument-Serif watermark numbers (.step-num, white/.05).
export function HowItWorks() {
  const { ref, visible } = useScrollReveal<HTMLElement>();

  return (
    <section ref={ref} id="workflow" className="mx-auto max-w-[1200px] px-7 py-20">
      <SectionHeading
        kicker="Get Started Fast"
        tone="sage"
        title="Live in Under 30 Minutes"
        body="No IT department. No onboarding calls. No configuration. Subscribe and start closing admits today."
        className={revealClass(visible)}
      />
      <div className="grid grid-cols-[repeat(auto-fit,minmax(200px,1fr))] gap-3">
        {HOW_IT_WORKS.map((s, i) => (
          <Card
            key={s.num}
            className={revealClass(visible)}
            style={staggerStyle(i + 1, visible)}
          >
            <CardContent className="p-6">
              <div className="mb-3 font-serif-display text-[48px] font-normal leading-none tracking-[-0.04em] text-white/[0.05]">
                {s.num}
              </div>
              <h3 className="mb-[7px] text-sm font-bold text-foreground">
                {s.title}
              </h3>
              <p className="text-[13px] leading-[1.64] text-muted">{s.body}</p>
            </CardContent>
          </Card>
        ))}
      </div>
    </section>
  );
}
