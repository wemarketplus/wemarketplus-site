import { Button, Card, CardContent } from '@/shared/ui/core';
import { ALERT_TONE_CLASS } from '../constants/billingConstants';
import type { BillingAlertProps } from '../types/billingTypes';

// Presentational alert card for a subscription problem (past-due, suspended,
// canceled). One reusable component instead of three near-identical inline cards.
export function BillingAlert({
  icon: Icon,
  tone,
  title,
  description,
  actionLabel,
  onAction,
  actionDisabled,
}: BillingAlertProps) {
  return (
    <Card>
      <CardContent className="flex items-start gap-4 px-6 py-5">
        <div
          className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-md ring-1 ${ALERT_TONE_CLASS[tone]}`}
        >
          <Icon className="h-5 w-5" />
        </div>
        <div className="flex-1">
          <h2 className="text-base font-semibold text-foreground">{title}</h2>
          <p className="mt-1 text-sm text-muted">{description}</p>
        </div>
        <Button onClick={onAction} disabled={actionDisabled}>
          {actionLabel}
        </Button>
      </CardContent>
    </Card>
  );
}
