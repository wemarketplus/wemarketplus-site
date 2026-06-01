import { TRUST_BADGES } from '../../constants/landingContent';

// index.html trust strip — 5 inline badges.
export function TrustBadges() {
  return (
    <section className="border-y border-white/[0.06]">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-center gap-x-10 gap-y-4 px-6 py-8">
        {TRUST_BADGES.map((b) => (
          <div key={b.title} className="text-center">
            <p className="text-sm font-bold text-foreground">{b.title}</p>
            <p className="text-[11px] uppercase tracking-[0.08em] text-muted-soft">
              {b.sub}
            </p>
          </div>
        ))}
      </div>
    </section>
  );
}
