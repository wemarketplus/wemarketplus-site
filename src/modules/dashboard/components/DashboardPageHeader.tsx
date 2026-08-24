import { OVERLINE, PAGE_SUBTITLE, PAGE_TITLE } from '@/shared/ui/core';
import { PRODUCT_LABELS, TIER_LABELS } from '@/shared/types';
import { ROLE_LABELS } from '@/shared/rbac';
import type { Role } from '@/shared/rbac';
import type { Product, Tier } from '@/shared/types';

interface DashboardPageHeaderProps {
  greeting: string;
  name: string;
  role: Role | null;
  /** The user's display title (custom role name when they hold one). */
  title?: string;
  product: Product;
  tier: Tier;
  organizationName: string;
  period: string;
  // When false (unpaid / incomplete tenant) the tier pill is hidden — a signup
  // that hasn't checked out shouldn't advertise a "PRO" plan it isn't on.
  hasActivePlan: boolean;
}

// Mirrors wemarketplus-site dashboards: page title, tenant + period
// subtitle, and a small tier badge. Single-component-per-file rule means
// this lives in its own component instead of inlining in DashboardPage.
export function DashboardPageHeader({
  greeting,
  name,
  role,
  title,
  product,
  tier,
  organizationName,
  period,
  hasActivePlan,
}: DashboardPageHeaderProps) {
  return (
    <header className="space-y-2">
      <div className="flex items-center gap-2">
        <p className={OVERLINE}>
          {greeting} · {PRODUCT_LABELS[product]}
        </p>
        {/* Only show the plan tier when billing is live; an unpaid signup
            (subscriptionStatus 'incomplete') shows no plan pill. */}
        {hasActivePlan && (
          <span className="rounded-pill border border-primary/40 bg-primary/15 px-2 py-0.5 text-[10px] font-bold uppercase tracking-label text-primary">
            {TIER_LABELS[tier]}
          </span>
        )}
      </div>
      {/*
        PAGE_TITLE, the same 30px every other screen's <h1> uses. This was
        `text-4xl leading-none` — 36px — so the home dashboard's title was 20%
        larger than the identically-positioned title on all 48 other pages. It
        is the "some headings appear excessively large and bold, while similar
        headings on other screens are smaller" report: nothing about this screen
        makes its name a bigger thing than "Lead pipeline" is on the next one.
      */}
      <h1 className={PAGE_TITLE}>{name}</h1>
      <p className={PAGE_SUBTITLE}>
        <span className="text-foreground">{organizationName}</span>
        <span className="mx-2 text-muted-soft">—</span>
        <span>{period}</span>
        {role && (
          <>
            <span className="mx-2 text-muted-soft">·</span>
            <span>Signed in as {title ?? ROLE_LABELS[role] ?? role}</span>
          </>
        )}
      </p>
    </header>
  );
}
