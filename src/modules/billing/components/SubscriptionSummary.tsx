import { Card, CardContent } from '@/shared/ui/core';
import { PlanCard } from './PlanCard';
import { formatPeriodEnd, statusLabel, statusToneClass } from '../utils/billingUtils';
import type { SubscriptionSummaryProps } from '../types/billingTypes';

// Presentational summary of the active subscription: the plan card plus a
// status panel (state badge + renewal / scheduled-deletion dates).
export function SubscriptionSummary({ data }: SubscriptionSummaryProps) {
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      <div className="lg:col-span-2">
        <PlanCard
          product={data.product}
          plan={data.plan}
          organizationName={data.organizationName}
        />
      </div>
      <Card>
        <CardContent className="space-y-3 px-6 py-6">
          <p className="text-[10px] uppercase tracking-label text-muted-soft">
            Status
          </p>
          <span
            className={`inline-flex items-center gap-1.5 rounded-pill border px-3 py-1 text-xs font-semibold uppercase tracking-label ${statusToneClass(data.status)}`}
          >
            {statusLabel(data.status)}
          </span>
          <p className="text-sm text-muted">
            Renews on{' '}
            <span className="text-foreground">
              {formatPeriodEnd(data.currentPeriodEnd)}
            </span>
            .
          </p>
          {data.scheduledDeleteAt && (
            <p className="text-xs text-warning">
              Data will be removed on {formatPeriodEnd(data.scheduledDeleteAt)}.
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
