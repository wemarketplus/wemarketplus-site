import { Card, CardContent } from '@/shared/ui/core';
import { TESTIMONIALS } from '../../constants/landingContent';

// index.html "What Hospice Teams Are Saying" — 3 cards, 5-star.
export function Testimonials() {
  return (
    <section className="mx-auto max-w-7xl px-6 py-20">
      <div className="mb-10 text-center">
        <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-sage">
          Client Results
        </p>
        <h2 className="mt-3 font-serif-display text-3xl font-black text-foreground sm:text-4xl">
          What Hospice Teams Are Saying
        </h2>
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {TESTIMONIALS.map((t) => (
          <Card key={t.name}>
            <CardContent className="space-y-4 px-6 py-6">
              <div className="text-amber" aria-hidden>★★★★★</div>
              <p className="text-sm leading-relaxed text-foreground">“{t.quote}”</p>
              <div>
                <p className="text-sm font-bold text-foreground">{t.name}</p>
                <p className="text-xs text-muted">{t.role}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </section>
  );
}
