import { PRODUCT_LABELS, TIER_LABELS, type Product, type Tier } from '@/shared/types';
import { Card, CardContent } from '@/shared/ui/core';

interface PlanCardProps {
  product: Product;
  plan: Tier;
  organizationName: string;
}

export function PlanCard({ product, plan, organizationName }: PlanCardProps) {
  return (
    <Card className="overflow-hidden">
      <CardContent className="space-y-3 px-6 py-6">
        <p className="text-[10px] uppercase tracking-[0.14em] text-muted-soft">
          Your plan
        </p>
        <div className="flex items-baseline gap-3">
          <h2 className="font-display text-3xl text-foreground">
            {PRODUCT_LABELS[product]}
          </h2>
          <span className="rounded-pill border border-primary/40 bg-primary/15 px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-[0.08em] text-primary">
            {TIER_LABELS[plan]}
          </span>
        </div>
        <p className="text-sm text-muted">{organizationName}</p>
      </CardContent>
    </Card>
  );
}
