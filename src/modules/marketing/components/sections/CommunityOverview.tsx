import { Link } from 'react-router-dom';
import { Card, CardContent, Button } from '@/shared/ui/core';
import { SectionHeading } from '../SectionHeading';
import { CommunityPlanCard } from '../CommunityPlanCard';
import { COMMUNITYLINK_PLANS } from '../../constants/communityPricingPlans';
import {
  COMMUNITY_PILLARS,
  COMMUNITY_TILES,
} from '../../constants/landingContent';
import { cn } from '@/shared/utils/cn';

const PILLAR_BORDER: Record<string, string> = {
  amber: 'border-amber/30',
  sage: 'border-sage/30',
  azure: 'border-azure/30',
};

// index.html #communitylink — product divider + 3 value pillars + 8 tiles.
export function CommunityOverview() {
  return (
    <section
      id="communitylink"
      data-product="communitylink"
      className="border-y border-white/[0.06]"
      style={{
        background:
          'linear-gradient(135deg, #0a1628 0%, #0d1f38 50%, #0a1628 100%)',
      }}
    >
      <div className="mx-auto max-w-7xl px-6 py-20">
        <div className="text-center">
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-amber">
            🏠 Solutions for Senior Living &amp; Assisted Living Teams
          </p>
          <h2 className="mt-3 font-serif-display text-4xl font-black text-foreground">
            CommunityLink <span className="text-amber">CRM</span>
          </h2>
          <p className="mx-auto mt-4 max-w-2xl text-base text-muted">
            The all-in-one sales, operations, and financial command center built for
            Independent Living, Assisted Living &amp; Memory Care communities.
          </p>
          <p className="mx-auto mt-2 max-w-2xl text-sm text-muted-soft">
            From first inquiry to move-in, make-ready workflows to investor reports —
            CommunityLink puts your entire community in one place.
          </p>
        </div>

        <div className="mt-10 grid grid-cols-1 gap-4 lg:grid-cols-3">
          {COMMUNITY_PILLARS.map((p) => (
            <Card key={p.title} className={cn('border', PILLAR_BORDER[p.tone])}>
              <CardContent className="space-y-2 px-6 py-6">
                <h3 className="text-base font-bold text-foreground">{p.title}</h3>
                <p className="text-sm leading-relaxed text-muted">{p.body}</p>
              </CardContent>
            </Card>
          ))}
        </div>

        <div className="mt-6 flex flex-wrap justify-center gap-2">
          <Link to="/demo/communitylink/pro">
            <Button variant="secondary" size="sm">View Pro Demo</Button>
          </Link>
          <Link to="/demo/communitylink/gold">
            <Button variant="secondary" size="sm">View Gold Demo</Button>
          </Link>
          <Link to="/demo/communitylink/max">
            <Button variant="secondary" size="sm">View Max Demo</Button>
          </Link>
          <Link to="/#cl-pricing">
            <Button size="sm">See Pricing ↓</Button>
          </Link>
        </div>

        <div className="mt-14">
          <SectionHeading
            kicker="Built for Senior Living"
            tone="amber"
            title="Everything Your Community Needs in One Platform"
            body="Purpose-built for independent living, assisted living, and memory care operations teams."
          />
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {COMMUNITY_TILES.map((t) => (
            <Card key={t.title}>
              <CardContent className="space-y-2 px-5 py-5">
                <div className="text-2xl" aria-hidden>{t.icon}</div>
                <h4 className="text-sm font-bold text-foreground">{t.title}</h4>
                <p className="text-[13px] leading-relaxed text-muted">{t.body}</p>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* CommunityLink pricing — "Plans for Every Community" */}
        <div id="cl-pricing" className="mt-14">
          <SectionHeading
            kicker="CommunityLink Pricing"
            tone="amber"
            title="Plans for Every Community"
            body="Per facility pricing. No hidden fees. Cancel anytime."
          />
          <div className="grid grid-cols-1 gap-[18px] md:grid-cols-3">
            {COMMUNITYLINK_PLANS.map((plan) => (
              <CommunityPlanCard key={plan.eyebrow} plan={plan} />
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
