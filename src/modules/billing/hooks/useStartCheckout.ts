import { useState } from 'react';
import { toast } from 'sonner';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { useCreateCheckoutSessionMutation } from '../api/billingApi';

// Starts a Stripe Checkout (subscription mode) and redirects the browser to the
// hosted Checkout page. `choosePlan` buys a specific catalog plan and tracks
// which plan is mid-redirect (busyPlanKey) so the picker can show per-card busy
// state. On return, the webhook activates the subscription and sets the tenant
// tier, so /billing reflects the live status.
export function useStartCheckout() {
  const [createCheckout, { isLoading }] = useCreateCheckoutSessionMutation();
  const [busyPlanKey, setBusyPlanKey] = useState<string | null>(null);

  const startCheckout = async (planKey?: string) => {
    if (planKey) setBusyPlanKey(planKey);
    try {
      const { url } = await createCheckout(
        planKey ? { planKey } : undefined,
      ).unwrap();
      window.location.href = url;
    } catch (err) {
      setBusyPlanKey(null);
      toast.error(extractApiErrorMessage(err, "Couldn't start checkout"));
    }
  };

  return { startCheckout, busyPlanKey, isLoading };
}
