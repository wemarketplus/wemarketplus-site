import { PAGE_TITLE } from '@/shared/ui/core/typography';
// Presentational page header for the subscription & billing screen.
export function BillingHeader() {
  return (
    <div className="space-y-1">
      <h1 className={PAGE_TITLE}>
        Subscription &amp; billing
      </h1>
      <p className="text-sm text-muted">
        Manage your plan, payment method, and invoices.
      </p>
    </div>
  );
}
