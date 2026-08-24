import { ArrowUpRight, Check } from 'lucide-react';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { PRODUCT_LABELS } from '@/shared/types';
import { PLAN_FEATURE_LABELS, UNLIMITED_SEATS } from '../constants/billingConstants';
import type { PlanPickerProps } from '../types/billingTypes';

// Renders the configured plan catalog as selectable cards. Each "Choose"
// starts a Stripe Checkout for that plan via the parent's onChoose handler.
export function PlanPicker({ plans, isLoading, busyPlanKey, onChoose }: PlanPickerProps) {
  if (isLoading) {
    return (
      <Card>
        <CardContent className="px-6 py-8 text-sm text-muted">
          Loading plans…
        </CardContent>
      </Card>
    );
  }

  if (plans.length === 0) {
    return (
      <Card>
        <CardContent className="px-6 py-8 text-sm text-muted">
          No plans are available right now. Please check back shortly.
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
      {plans.map((plan) => {
        const busy = busyPlanKey === plan.key;
        const featureLabels = (plan.features ?? [])
          .map((key) => PLAN_FEATURE_LABELS[key])
          .filter((label): label is string => Boolean(label));
        return (
          <Card key={plan.key}>
            <CardContent className="flex h-full flex-col gap-4 px-6 py-6">
              <div className="space-y-1">
                <p className="text-[10px] uppercase tracking-label text-muted-soft">
                  {PRODUCT_LABELS[plan.product]}
                </p>
                <h3 className="text-lg font-semibold text-foreground">{plan.name}</h3>
                <p className="text-2xl font-bold text-foreground">{plan.price}</p>
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
                <Button
                  className="w-full"
                  onClick={() => onChoose(plan.key)}
                  disabled={busy}
                >
                  {busy ? 'Redirecting…' : 'Choose'}
                  {!busy && <ArrowUpRight className="h-4 w-4" />}
                </Button>
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
