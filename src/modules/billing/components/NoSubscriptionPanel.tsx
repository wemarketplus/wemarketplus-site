import { SECTION_TITLE } from '@/shared/ui/core/typography';
import { Sparkles } from 'lucide-react';
import { Button, Card, CardContent } from '@/shared/ui/core';
import type { NoSubscriptionPanelProps } from '../types/billingTypes';

// Presentational empty-state shown when the tenant has no paid plan. The plan
// catalog itself is rendered separately by PlanPicker.
export function NoSubscriptionPanel({ onGoToCrm }: NoSubscriptionPanelProps) {
  return (
    <Card>
      <CardContent className="flex flex-col gap-4 px-6 py-6 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-start gap-4">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-primary/15 text-primary ring-1 ring-primary/30">
            <Sparkles className="h-5 w-5" />
          </div>
          <div>
            <h2 className={SECTION_TITLE}>
              No active subscription
            </h2>
            <p className="mt-1 max-w-xl text-sm text-muted">
              Your workspace doesn&apos;t have a paid plan yet. Choose a plan
              below to unlock the full CRM — you can keep exploring in the
              meantime.
            </p>
          </div>
        </div>
        <Button variant="secondary" onClick={onGoToCrm}>
          Go to my CRM
        </Button>
      </CardContent>
    </Card>
  );
}
