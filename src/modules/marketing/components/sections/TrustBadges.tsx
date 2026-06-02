import { TRUST_BADGES } from '../../constants/landingContent';
import { TrustBadgePill } from '../TrustBadgePill';

// index.html trust strip — 5 inline icon-pill badges in one balanced row.
export function TrustBadges() {
  return (
    <section className="border-y border-white/[0.06]">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-center gap-3 px-6 py-8">
        {TRUST_BADGES.map((b) => (
          <TrustBadgePill key={b.title} badge={b} />
        ))}
      </div>
    </section>
  );
}
