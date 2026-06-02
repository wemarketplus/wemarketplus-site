import { Link } from 'react-router-dom';
import {
  DollarSign,
  Home,
  Monitor,
  Users,
  type LucideIcon,
} from 'lucide-react';
import { Card, CardContent } from '@/shared/ui/core';
import { SectionHeading } from '../SectionHeading';
import { CommunityPlanCard } from '../CommunityPlanCard';
import { COMMUNITYLINK_PLANS } from '../../constants/communityPricingPlans';
import {
  COMMUNITY_PILLARS,
  COMMUNITY_TILES,
} from '../../constants/landingContent';
import {
  PILLAR_BORDER,
  PILLAR_ICON_TILE,
} from '../../constants/interactionConstants';
import type { CommunityPillarIcon } from '../../types/landingTypes';
import { cn } from '@/shared/utils/cn';

// Pillar icon key → component (components reference components; the tone→class
// maps live in constants).
const PILLAR_ICON: Record<CommunityPillarIcon, LucideIcon> = {
  sales: Users,
  operations: Monitor,
  financial: DollarSign,
};

// index.html #communitylink — product divider + 3 value pillars + 8 tiles.
export function CommunityOverview() {
  return (
    <section
      id="communitylink"
      data-product="communitylink"
      className="border-y border-white/[0.06]"
      style={{
        // Near-ink backdrop matching the reference "Built for Senior Living"
        // band: a barely-there dark navy gradient so the bordered cards read as
        // a slightly lighter surface against the dark page (not the old bright
        // blue band, which washed out the card borders).
        background:
          'linear-gradient(135deg, #070b13 0%, #0a1020 50%, #070b13 100%)',
      }}
    >
      <div className="mx-auto max-w-7xl px-6 pb-20 pt-16">
        <div className="mx-auto max-w-4xl text-center">
          {/* Eyebrow pill + logo + wordmark share one centred row (wraps on
              narrow screens), matching the reference header. */}
          <div className="flex flex-wrap items-center justify-center gap-x-5 gap-y-3">
            <span className="inline-flex items-center gap-2 rounded-pill border border-amber/[0.25] bg-amber/10 px-5 py-2 text-[13px] font-bold tracking-[0.04em] text-amber">
              🏠 Solutions for Senior Living &amp; Assisted Living Teams
            </span>
            <div className="flex items-center gap-3">
              <span className="flex h-11 w-11 items-center justify-center rounded-[12px] bg-[linear-gradient(135deg,#f59e0b,#ef8c03)] text-[#06080e]">
                <Home className="h-[22px] w-[22px]" strokeWidth={2.2} />
              </span>
              <h2 className="text-[36px] font-black leading-none tracking-[-0.02em] text-foreground">
                CommunityLink <span className="text-amber">CRM</span>
              </h2>
            </div>
          </div>
          <p className="mx-auto mt-6 max-w-2xl text-[17px] leading-[1.7] text-muted">
            The all-in-one sales, operations, and financial command center built for{' '}
            <span className="font-semibold text-foreground">
              Independent Living, Assisted Living &amp; Memory Care
            </span>{' '}
            communities.
          </p>
          <p className="mx-auto mt-3 max-w-xl text-sm leading-[1.7] text-muted-soft">
            From first inquiry to move-in, make-ready workflows to investor reports —
            CommunityLink puts your entire community in one place.
          </p>
        </div>

        <div className="mt-10 grid auto-rows-fr grid-cols-1 gap-4 lg:grid-cols-3">
          {COMMUNITY_PILLARS.map((p) => {
            const Icon = PILLAR_ICON[p.icon];
            return (
              <Card
                key={p.title}
                className={cn('h-full rounded-[16px] border bg-[#081426]', PILLAR_BORDER[p.tone])}
              >
                <CardContent className="space-y-2 px-6 py-6">
                  <div
                    className={cn(
                      'mb-3 flex h-[38px] w-[38px] items-center justify-center rounded-[9px]',
                      PILLAR_ICON_TILE[p.tone],
                    )}
                  >
                    <Icon className="h-[19px] w-[19px]" strokeWidth={1.8} />
                  </div>
                  <h3 className="text-base font-bold text-foreground">{p.title}</h3>
                  <p className="text-sm leading-relaxed text-muted">{p.body}</p>
                </CardContent>
              </Card>
            );
          })}
        </div>

        {/* Demo buttons — exact styles from the live site: Pro filled amber,
            Gold amber-tinted, Max azure-tinted, See Pricing neutral outline. */}
        <div className="mt-8 flex flex-wrap justify-center gap-2.5">
          <Link
            to="/demo/communitylink/pro"
            className="rounded-pill bg-amber px-7 py-3.5 text-[14px] font-extrabold text-[#06080e] transition-opacity hover:opacity-[0.88]"
          >
            View Pro Demo
          </Link>
          <Link
            to="/demo/communitylink/gold"
            className="rounded-pill border border-amber/30 bg-amber/[0.12] px-7 py-3.5 text-[14px] font-bold text-amber transition-colors hover:bg-amber/[0.18]"
          >
            View Gold Demo
          </Link>
          <Link
            to="/demo/communitylink/max"
            className="rounded-pill border border-azure/25 bg-azure/10 px-7 py-3.5 text-[14px] font-bold text-azure transition-colors hover:bg-azure/[0.16]"
          >
            View Max Demo
          </Link>
          <Link
            to="/#cl-pricing"
            className="rounded-pill border border-white/[0.15] px-7 py-3.5 text-[14px] font-semibold text-[#c8d6e8] transition-colors hover:border-white/[0.28] hover:text-foreground"
          >
            See Pricing ↓
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
        <div className="grid auto-rows-fr grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {COMMUNITY_TILES.map((t) => (
            <Card key={t.title} className="h-full">
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
          <div className="grid auto-rows-fr grid-cols-1 gap-[18px] md:grid-cols-3">
            {COMMUNITYLINK_PLANS.map((plan) => (
              <CommunityPlanCard key={plan.eyebrow} plan={plan} />
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
