import { Card, CardContent } from '@/shared/ui/core';
import { SectionHeading } from '../SectionHeading';
import { TrustBadgePill } from '../TrustBadgePill';
import { TRUST_BADGES } from '../../constants/landingContent';

// index.html "TESTIMONIALS + SOCIAL PROOF" — second testi-grid ("What Hospice
// & Senior Living Teams Say") plus a HIPAA / BAA / guarantee trust row.
const QUOTES = [
  {
    quote:
      'We went from tracking referrals in three different spreadsheets to having everything in one place. Our admit rate went up 31% in the first quarter.',
    name: 'Sarah M.',
    role: 'Director of Business Development — DFW Hospice Network',
  },
  {
    quote:
      'Setup literally took 25 minutes. I imported my prospect list, logged my first touch, and had the AI triage running before lunch. No IT. No training calls.',
    name: 'Marcus J.',
    role: 'Community Liaison — North Texas Palliative Care',
  },
  {
    quote:
      'CommunityLink helped us reduce our average days-to-lease from 41 days to 24. The referral pipeline and lead scoring actually work. I tell everyone.',
    name: 'Diane R.',
    role: 'Executive Director — Sunrise Senior Living, Plano TX',
  },
];

export function SocialProof() {
  return (
    <section className="mx-auto max-w-[1200px] px-7 py-12">
      <SectionHeading
        kicker="Trusted by Healthcare Teams"
        tone="sage"
        title="What Hospice & Senior Living Teams Say"
        body="Real results from teams who replaced spreadsheets with HospiceLink and CommunityLink."
      />
      {/* Cards capped to a tighter width so they read as a balanced trio rather
          than stretching across the full container. */}
      <div className="mx-auto grid max-w-[1040px] grid-cols-[repeat(auto-fit,minmax(280px,1fr))] gap-3.5">
        {QUOTES.map((t) => (
          <Card key={t.name} className="rounded-[16px]">
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
      {/* HIPAA / BAA / guarantee trust strip — one balanced row of icon pills. */}
      <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
        {TRUST_BADGES.map((b) => (
          <TrustBadgePill key={b.title} badge={b} />
        ))}
      </div>
    </section>
  );
}
