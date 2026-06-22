import { useNavigate } from 'react-router-dom';
import { Card, CardContent } from '@/shared/ui/core';
import { useSubscription } from '../hooks/useSubscription';
import { useBillingPortal } from '../hooks/useBillingPortal';
import { useStartCheckout } from '../hooks/useStartCheckout';
import { usePlans } from '../hooks/usePlans';
import { useCheckoutReturn } from '../hooks/useCheckoutReturn';
import { useSubscriptionAlert } from '../hooks/useSubscriptionAlert';
import { BillingHeader } from '../components/BillingHeader';
import { NoSubscriptionPanel } from '../components/NoSubscriptionPanel';
import { PlanPicker } from '../components/PlanPicker';
import { SubscriptionSummary } from '../components/SubscriptionSummary';
import { BillingAlert } from '../components/BillingAlert';
import { UpgradePanel } from '../components/UpgradePanel';

export function SubscriptionStatusPage() {
  const navigate = useNavigate();
  const { data, isLoading, hasSubscription, refetch } = useSubscription();
  const { goToPortal, isLoading: portalLoading } = useBillingPortal();
  const { startCheckout, busyPlanKey } = useStartCheckout();
  const { plans, isLoading: plansLoading } = usePlans();
  const alert = useSubscriptionAlert(data);

  useCheckoutReturn(refetch);

  const goToCrm = () => navigate('/');

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

  if (!hasSubscription) {
    return (
      <div className="space-y-6">
        <BillingHeader />
        <NoSubscriptionPanel onGoToCrm={goToCrm} />
        <PlanPicker
          plans={plans}
          isLoading={plansLoading}
          busyPlanKey={busyPlanKey}
          onChoose={startCheckout}
        />
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
          actionDisabled={portalLoading}
        />
      )}
      <UpgradePanel
        onGoToCrm={goToCrm}
        onManageBilling={goToPortal}
        manageDisabled={portalLoading}
      />
    </div>
  );
}
