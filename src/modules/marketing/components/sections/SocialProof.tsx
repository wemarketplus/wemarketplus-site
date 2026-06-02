import { Card, CardContent } from '@/shared/ui/core';
import { SectionHeading } from '../SectionHeading';

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

const TRUST = [
  { title: 'HIPAA Compliant', sub: 'TLS 1.3 · AES-256' },
  { title: 'BAA Included', sub: 'Signed at checkout' },
  { title: '30-Day Guarantee', sub: 'Full refund, no questions' },
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
      <div className="grid grid-cols-[repeat(auto-fit,minmax(280px,1fr))] gap-3.5">
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
      <div className="mt-9 flex flex-wrap items-center justify-center gap-x-10 gap-y-4">
        {TRUST.map((b) => (
          <div key={b.title} className="text-center">
            <p className="text-sm font-bold text-foreground">{b.title}</p>
            <p className="text-[11px] uppercase tracking-[0.08em] text-faint">
              {b.sub}
            </p>
          </div>
        ))}
      </div>
    </section>
  );
}
