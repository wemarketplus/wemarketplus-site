import { Card, CardContent } from '@/shared/ui/core';
import { useScrollReveal } from '@/shared/hooks';
import { cn } from '@/shared/utils/cn';
import { revealClass, staggerStyle } from '@/shared/utils/scrollReveal';
import { SectionHeading } from '../SectionHeading';
import { TESTIMONIALS } from '../../constants/landingContent';

// index.html "What Hospice Teams Are Saying" — 3 cards, 5-star.
export function Testimonials() {
  const { ref, visible } = useScrollReveal<HTMLElement>();

  return (
    <section ref={ref} className="mx-auto max-w-[1200px] px-7 py-20">
      <SectionHeading
        kicker="Client Results"
        tone="amber"
        title="What Hospice Teams Are Saying"
        className={revealClass(visible)}
      />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {TESTIMONIALS.map((t, i) => (
          <Card
            key={t.name}
            className={cn('rounded-[16px]', revealClass(visible))}
            style={staggerStyle(i + 1, visible)}
          >
            <CardContent className="p-[26px]">
              <div className="mb-3.5 flex gap-[3px] text-[13px] text-amber" aria-hidden>
                ★★★★★
              </div>
              <p className="mb-[18px] font-serif-display text-[15px] italic leading-[1.7] text-[#c9d6e4]">
                “{t.quote}”
              </p>
              <p className="text-[13px] font-bold text-foreground">{t.name}</p>
              <p className="mt-0.5 text-[11px] text-faint">{t.role}</p>
            </CardContent>
          </Card>
        ))}
      </div>
    </section>
  );
}
