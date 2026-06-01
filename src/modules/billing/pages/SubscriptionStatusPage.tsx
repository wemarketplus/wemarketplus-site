import {
  AlertTriangle,
  ArrowUpRight,
  CreditCard,
  RotateCcw,
  Sparkles,
} from 'lucide-react';
import { toast } from 'sonner';
import { useNavigate } from 'react-router-dom';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { SubscriptionStatus } from '@/shared/types';
import { useSubscription } from '../hooks/useSubscription';
import { useOpenPortalSessionMutation } from '../api/billingApi';
import { extractApiErrorMessage } from '@/modules/auth/utils/errorUtils';
import { PlanCard } from '../components/PlanCard';
import {
  formatPeriodEnd,
  statusLabel,
  statusToneClass,
} from '../utils/billingUtils';

export function SubscriptionStatusPage() {
  const navigate = useNavigate();
  const { data, isUsingFixture } = useSubscription();
  const [openPortal, portalState] = useOpenPortalSessionMutation();

  const goToPortal = async () => {
    try {
      const { url } = await openPortal().unwrap();
      window.location.href = url;
    } catch (err) {
      toast.error(extractApiErrorMessage(err, "Couldn't open billing portal"));
    }
  };

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="font-display text-3xl text-foreground">
          Subscription &amp; billing
        </h1>
        <p className="text-sm text-muted">
          Manage your plan, payment method, and invoices.
          {isUsingFixture && (
            <span className="ml-2 rounded-pill bg-white/[0.04] px-2 py-0.5 text-[10px] uppercase tracking-[0.1em] text-muted-soft">
              Preview data
            </span>
          )}
        </p>
      </div>

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
            <p className="text-[10px] uppercase tracking-[0.14em] text-muted-soft">
              Status
            </p>
            <span
              className={`inline-flex items-center gap-1.5 rounded-pill border px-3 py-1 text-xs font-semibold uppercase tracking-[0.08em] ${statusToneClass(data.status)}`}
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

      {data.status === SubscriptionStatus.PastDue && (
        <Card>
          <CardContent className="flex items-start gap-4 px-6 py-5">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-warning/15 text-warning ring-1 ring-warning/30">
              <AlertTriangle className="h-5 w-5" />
            </div>
            <div className="flex-1">
              <h2 className="text-base font-semibold text-foreground">
                Your last payment failed
              </h2>
              <p className="mt-1 text-sm text-muted">
                Update your card to keep your workspace active.
              </p>
            </div>
            <Button onClick={goToPortal} disabled={portalState.isLoading}>
              <CreditCard className="h-4 w-4" /> Update payment method
            </Button>
          </CardContent>
        </Card>
      )}

      {data.status === SubscriptionStatus.Suspended && (
        <Card>
          <CardContent className="flex items-start gap-4 px-6 py-5">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-destructive/15 text-destructive ring-1 ring-destructive/30">
              <AlertTriangle className="h-5 w-5" />
            </div>
            <div className="flex-1">
              <h2 className="text-base font-semibold text-foreground">
                Workspace temporarily suspended
              </h2>
              <p className="mt-1 text-sm text-muted">
                Restore access by settling your balance — no data has been
                deleted.
              </p>
            </div>
            <Button onClick={goToPortal} disabled={portalState.isLoading}>
              Restore access now
            </Button>
          </CardContent>
        </Card>
      )}

      {data.status === SubscriptionStatus.Canceled && (
        <Card>
          <CardContent className="flex items-start gap-4 px-6 py-5">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-destructive/15 text-destructive ring-1 ring-destructive/30">
              <RotateCcw className="h-5 w-5" />
            </div>
            <div className="flex-1">
              <h2 className="text-base font-semibold text-foreground">
                Subscription canceled
              </h2>
              <p className="mt-1 text-sm text-muted">
                You can reactivate any time before{' '}
                {data.scheduledDeleteAt
                  ? formatPeriodEnd(data.scheduledDeleteAt)
                  : 'your data is purged'}
                .
              </p>
            </div>
            <Button onClick={goToPortal} disabled={portalState.isLoading}>
              Reactivate
            </Button>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent className="flex flex-col gap-4 px-6 py-5 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-start gap-4">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-primary/15 text-primary ring-1 ring-primary/30">
              <Sparkles className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-foreground">
                Need more horsepower?
              </h2>
              <p className="mt-1 text-sm text-muted">
                Compare tiers and upgrade in the billing portal — change takes
                effect immediately.
              </p>
            </div>
          </div>
          <div className="flex gap-2">
            <Button variant="secondary" onClick={() => navigate('/')}>
              Go to my CRM
            </Button>
            <Button onClick={goToPortal} disabled={portalState.isLoading}>
              Manage billing <ArrowUpRight className="h-4 w-4" />
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
