import { useState } from 'react';
import { toast } from 'sonner';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import {
  useChangePlanMutation,
  usePreviewPlanChangeMutation,
} from '../api/billingApi';
import type { PlanChangePreview } from '../types/billingTypes';

// Orchestrates the in-app plan change (upgrade/downgrade) without leaving the
// app: selecting a plan runs the Stripe proration preview, the caller shows a
// confirmation dialog, and confirm applies the change replaying the previewed
// prorationDate so the charge matches exactly. `onApplied` (e.g. subscription
// refetch) fires after a successful change. The dialog is driven by `preview`
// (non-null while awaiting confirmation).
export function usePlanChange(onApplied: () => void) {
  const [runPreview] = usePreviewPlanChangeMutation();
  const [runChange] = useChangePlanMutation();
  const [previewingKey, setPreviewingKey] = useState<string | null>(null);
  const [preview, setPreview] = useState<PlanChangePreview | null>(null);
  const [applying, setApplying] = useState(false);

  // Step 1: fetch the proration preview for a target plan and open the dialog.
  const selectPlan = async (planKey: string) => {
    setPreviewingKey(planKey);
    try {
      const result = await runPreview({ planKey }).unwrap();
      setPreview(result);
    } catch (err) {
      toast.error(extractApiErrorMessage(err, "Couldn't preview this plan change"));
    } finally {
      setPreviewingKey(null);
    }
  };

  const cancel = () => setPreview(null);

  // Step 2: apply the change, replaying the previewed prorationDate.
  const confirm = async () => {
    if (!preview) return;
    setApplying(true);
    try {
      const result = await runChange({
        planKey: preview.newPlanKey,
        prorationDate: preview.prorationDate,
      }).unwrap();
      setPreview(null);
      // An upgrade with an amount due returns Stripe's hosted invoice page —
      // send the customer there to complete the proration payment. The webhook
      // converges local state once the invoice is paid.
      if (result.paymentUrl) {
        window.location.href = result.paymentUrl;
        return;
      }
      toast.success('Your plan has been updated');
      onApplied();
    } catch (err) {
      toast.error(extractApiErrorMessage(err, "Couldn't change your plan"));
    } finally {
      setApplying(false);
    }
  };

  return { selectPlan, previewingKey, preview, applying, confirm, cancel };
}
