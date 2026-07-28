import { ArrowUpRight, Check, RefreshCw } from 'lucide-react';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { PRODUCT_LABELS } from '@/shared/types';
import { PLAN_FEATURE_LABELS, UNLIMITED_SEATS } from '../constants/billingConstants';
import type { PlanOption } from '../types/billingTypes';

interface ChangePlanPanelProps {
  plans: readonly PlanOption[];
  isLoading: boolean;
  // The tenant's current plan key, so it is excluded / marked as current.
  currentPlanKey?: string;
  // Plan key mid-preview (awaiting the proration lookup), for per-card busy state.
  previewingKey: string | null;
  onSelect: (planKey: string) => void;
}

// Lists the other catalog plans an active subscriber can switch to in-app.
// Selecting one runs the proration preview (parent opens the confirm dialog).
// Distinct from PlanPicker (first-time checkout) — this is a plan change.
export function ChangePlanPanel({
  plans,
  isLoading,
  currentPlanKey,
  previewingKey,
  onSelect,
}: ChangePlanPanelProps) {
  if (isLoading || plans.length === 0) {
    return null;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <RefreshCw className="h-4 w-4 text-primary" />
        <h2 className="text-base font-semibold text-foreground">Change plan</h2>
      </div>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {plans.map((plan) => {
          const isCurrent = plan.key === currentPlanKey;
          const busy = previewingKey === plan.key;
          const featureLabels = (plan.features ?? [])
            .map((key) => PLAN_FEATURE_LABELS[key])
            .filter((label): label is string => Boolean(label));
          return (
            <Card key={plan.key}>
              <CardContent className="flex h-full flex-col gap-4 px-6 py-6">
                <div className="space-y-1">
                  <p className="text-[10px] uppercase tracking-[0.14em] text-muted-soft">
                    {PRODUCT_LABELS[plan.product]}
                  </p>
                  <h3 className="text-lg font-semibold text-foreground">{plan.name}</h3>
                  <p className="text-2xl font-bold text-foreground">{plan.price}</p>
                  {/* The price above is the recurring rate. Switching mid-cycle
                      charges only the prorated difference, so the confirm
                      dialog shows a smaller figure — say so here, or that gap
                      reads as a pricing bug. */}
                  {!isCurrent && (
                    <p className="text-xs text-muted-soft">
                      Switch today and you pay only the difference for the rest of
                      this billing period.
                    </p>
                  )}
                </div>
                <div className="flex items-center gap-2 text-sm text-muted">
                  <Check className="h-4 w-4 text-success" />
                  Up to {plan.seats >= UNLIMITED_SEATS ? 'unlimited' : plan.seats} users
                </div>
                {featureLabels.length > 0 && (
                  <ul className="space-y-1.5">
                    {featureLabels.map((label) => (
                      <li key={label} className="flex items-center gap-2 text-sm text-muted">
                        <Check className="h-4 w-4 text-success" />
                        {label}
                      </li>
                    ))}
                  </ul>
                )}
                <div className="mt-auto">
                  {isCurrent ? (
                    <Button className="w-full" variant="secondary" disabled>
                      Current plan
                    </Button>
                  ) : (
                    <Button
                      className="w-full"
                      onClick={() => onSelect(plan.key)}
                      disabled={busy || previewingKey !== null}
                    >
                      {busy ? 'Loading…' : 'Select'}
                      {!busy && <ArrowUpRight className="h-4 w-4" />}
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
