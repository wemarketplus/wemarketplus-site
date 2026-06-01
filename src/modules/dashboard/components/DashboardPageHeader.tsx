import { PRODUCT_LABELS, TIER_LABELS } from '@/shared/types';
import { ROLE_LABELS } from '@/shared/rbac';
import type { Role } from '@/shared/rbac';
import type { Product, Tier } from '@/shared/types';

interface DashboardPageHeaderProps {
  greeting: string;
  name: string;
  role: Role | null;
  product: Product;
  tier: Tier;
  organizationName: string;
  period: string;
}

// Mirrors wemarketplus-site dashboards: page title, tenant + period
// subtitle, and a small tier badge. Single-component-per-file rule means
// this lives in its own component instead of inlining in DashboardPage.
export function DashboardPageHeader({
  greeting,
  name,
  role,
  product,
  tier,
  organizationName,
  period,
}: DashboardPageHeaderProps) {
  return (
    <header className="space-y-2">
      <div className="flex items-center gap-2">
        <p className="text-[11px] uppercase tracking-[0.16em] text-muted-soft">
          {greeting} · {PRODUCT_LABELS[product]}
        </p>
        <span className="rounded-pill border border-primary/40 bg-primary/15 px-2 py-0.5 text-[10px] font-bold uppercase tracking-[0.1em] text-primary">
          {TIER_LABELS[tier]}
        </span>
      </div>
      <h1 className="font-display text-4xl leading-none text-foreground">
        {name}
      </h1>
      <p className="text-sm text-muted">
        <span className="text-foreground">{organizationName}</span>
        <span className="mx-2 text-muted-soft">—</span>
        <span>{period}</span>
        {role && (
          <>
            <span className="mx-2 text-muted-soft">·</span>
            <span>Signed in as {ROLE_LABELS[role] ?? role}</span>
          </>
        )}
      </p>
    </header>
  );
}
