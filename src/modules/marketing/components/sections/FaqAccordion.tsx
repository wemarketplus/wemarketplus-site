import { useState } from 'react';
import { FAQS } from '../../constants/landingContent';

// index.html #faq — expandable Q&A list with a + / − toggle marker.
export function FaqAccordion() {
  const [open, setOpen] = useState<number | null>(0);

  return (
    <section id="faq" className="mx-auto max-w-3xl px-6 py-20">
      <div className="mb-10 text-center">
        <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-sage">
          FAQ
        </p>
        <h2 className="mt-3 font-serif-display text-3xl font-black text-foreground sm:text-4xl">
          Frequently Asked Questions
        </h2>
      </div>
      <div className="space-y-2">
        {FAQS.map((f, i) => {
          const isOpen = open === i;
          return (
            <div
              key={f.q}
              className="overflow-hidden rounded-[12px] border border-white/[0.09] bg-surface"
            >
              <button
                type="button"
                onClick={() => setOpen(isOpen ? null : i)}
                aria-expanded={isOpen}
                className="flex w-full items-center justify-between gap-4 px-5 py-4 text-left"
              >
                <span className="text-sm font-bold text-foreground">{f.q}</span>
                <span
                  aria-hidden
                  className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-white/[0.06] text-lg leading-none text-muted"
                >
                  {isOpen ? '−' : '+'}
                </span>
              </button>
              {isOpen && (
                <p className="border-t border-white/[0.06] px-5 py-4 text-sm leading-relaxed text-muted">
                  {f.a}
                </p>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}
