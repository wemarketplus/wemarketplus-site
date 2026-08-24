import { SECTION_TITLE } from '@/shared/ui/core/typography';
import { ArrowUpRight, Sparkles } from 'lucide-react';
import { Button, Card, CardContent } from '@/shared/ui/core';
import type { UpgradePanelProps } from '../types/billingTypes';

// Presentational upsell shown to active subscribers — link out to the Stripe
// billing portal to compare tiers / upgrade.
export function UpgradePanel({
  onGoToCrm,
  onManageBilling,
  manageDisabled,
}: UpgradePanelProps) {
  return (
    <Card>
      <CardContent className="flex flex-col gap-4 px-6 py-5 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-start gap-4">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-primary/15 text-primary ring-1 ring-primary/30">
            <Sparkles className="h-5 w-5" />
          </div>
          <div>
            <h2 className={SECTION_TITLE}>
              Manage your billing
            </h2>
            <p className="mt-1 text-sm text-muted">
              Change plans above, or open the billing portal to update your
              payment method, view invoices, or cancel.
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="secondary" onClick={onGoToCrm}>
            Go to my CRM
          </Button>
          <Button onClick={onManageBilling} disabled={manageDisabled}>
            Manage billing <ArrowUpRight className="h-4 w-4" />
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
