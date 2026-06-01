import { Home } from 'lucide-react';

// index.html origin-story callout — "20+ Years in Hospice & Senior Living Sales".
export function OriginStory() {
  return (
    <section className="mx-auto max-w-3xl px-6 py-16">
      <div className="flex items-start gap-5 rounded-[18px] border border-white/[0.09] bg-surface p-8">
        <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-[12px] bg-sage/15 text-sage ring-1 ring-sage/20">
          <Home className="h-6 w-6" />
        </div>
        <div>
          <h2 className="font-serif-display text-2xl text-foreground">
            20+ Years in Hospice &amp; Senior Living Sales
          </h2>
          <p className="mt-3 text-sm leading-relaxed text-muted">
            HospiceLink was not built by software engineers guessing what hospice
            teams need. It was built by industry veterans who have personally worked
            referral relationships, sat in IDT meetings, managed census goals, and
            felt the pain of spreadsheet chaos. Every feature exists because someone
            on our team needed it in the field.
          </p>
        </div>
      </div>
    </section>
  );
}
