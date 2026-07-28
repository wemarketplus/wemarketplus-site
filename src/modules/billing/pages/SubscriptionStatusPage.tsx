import { useNavigate } from 'react-router-dom';
import { Card, CardContent } from '@/shared/ui/core';
import { ADMIN_ONLY, Role, useRole } from '@/shared/rbac';
import { useGetSubscriptionQuery } from '../api/billingApi';
import { useSubscription } from '../hooks/useSubscription';
import { useBillingPortal } from '../hooks/useBillingPortal';
import { useStartCheckout } from '../hooks/useStartCheckout';
import { usePlanChange } from '../hooks/usePlanChange';
import { usePlans } from '../hooks/usePlans';
import { useCheckoutReturn } from '../hooks/useCheckoutReturn';
import { useSubscriptionAlert } from '../hooks/useSubscriptionAlert';
import { BillingHeader } from '../components/BillingHeader';
import { NoSubscriptionPanel } from '../components/NoSubscriptionPanel';
import { PlanPicker } from '../components/PlanPicker';
import { ChangePlanPanel } from '../components/ChangePlanPanel';
import { PlanChangeDialog } from '../components/PlanChangeDialog';
import { SubscriptionSummary } from '../components/SubscriptionSummary';
import { BillingAlert } from '../components/BillingAlert';
import { UpgradePanel } from '../components/UpgradePanel';

export function SubscriptionStatusPage() {
  const navigate = useNavigate();
  const { data, isLoading, hasSubscription, refetch } = useSubscription();
  // Raw record for the catalog-resolved planKey (the view model drops it).
  const { data: record } = useGetSubscriptionQuery();
  const { goToPortal, isLoading: portalLoading } = useBillingPortal();
  const { startCheckout, busyPlanKey } = useStartCheckout();
  const { plans, isLoading: plansLoading } = usePlans();
  const {
    selectPlan,
    previewingKey,
    preview,
    applying,
    confirm,
    cancel,
  } = usePlanChange(refetch);
  const alert = useSubscriptionAlert(data);
  // Mirrors the backend gating: checkout/plan changes need Owner or Admin
  // (@Roles on BillingController); the Stripe portal (payment methods,
  // cancellation) is Owner-only. SuperAdmin bypasses both server-side.
  const { isAny, is } = useRole();
  const canManageBilling = isAny(ADMIN_ONLY);
  const canOpenPortal = is(Role.Owner) || is(Role.SuperAdmin);

  useCheckoutReturn(refetch);

  const goToCrm = () => navigate('/');
  const targetPlan = preview
    ? plans.find((p) => p.key === preview.newPlanKey)
    : undefined;

  if (isLoading) {
    return (
      <div className="space-y-6">
        <BillingHeader />
        <Card>
          <CardContent className="px-6 py-8 text-sm text-muted">
            Loading your subscription…
          </CardContent>
        </Card>
      </div>
    );
  }

  const readOnlyNotice = (
    <Card>
      <CardContent className="px-6 py-6 text-sm text-muted">
        Plan and payment changes are managed by your workspace owner or
        administrator.
      </CardContent>
    </Card>
  );

  if (!hasSubscription) {
    return (
      <div className="space-y-6">
        <BillingHeader />
        <NoSubscriptionPanel onGoToCrm={goToCrm} />
        {canManageBilling ? (
          <PlanPicker
            plans={plans}
            isLoading={plansLoading}
            busyPlanKey={busyPlanKey}
            onChoose={startCheckout}
          />
        ) : (
          readOnlyNotice
        )}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <BillingHeader />
      <SubscriptionSummary data={data} />
      {alert && (
        <BillingAlert
          icon={alert.icon}
          tone={alert.tone}
          title={alert.title}
          description={alert.description}
          actionLabel={alert.actionLabel}
          onAction={goToPortal}
          actionDisabled={portalLoading || !canOpenPortal}
        />
      )}
      {canManageBilling ? (
        <>
          <ChangePlanPanel
            plans={plans}
            isLoading={plansLoading}
            currentPlanKey={record?.planKey}
            previewingKey={previewingKey}
            onSelect={selectPlan}
          />
          <UpgradePanel
            onGoToCrm={goToCrm}
            onManageBilling={goToPortal}
            manageDisabled={portalLoading || !canOpenPortal}
          />
          <PlanChangeDialog
            preview={preview}
            targetPlan={targetPlan}
            applying={applying}
            renewsOn={data?.currentPeriodEnd}
            onConfirm={confirm}
            onCancel={cancel}
          />
        </>
      ) : (
        readOnlyNotice
      )}
    </div>
  );
}
