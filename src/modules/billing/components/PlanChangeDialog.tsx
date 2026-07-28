import { Button } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import type { PlanChangePreview, PlanOption } from '../types/billingTypes';
import { formatMinorAmount, formatPeriodEnd } from '../utils/billingUtils';

interface PlanChangeDialogProps {
  preview: PlanChangePreview | null;
  targetPlan?: PlanOption;
  applying: boolean;
  // End of the current paid period, so an upgrade can show when the plan's
  // regular monthly price takes over from the one-off prorated charge.
  renewsOn?: string;
  onConfirm: () => void;
  onCancel: () => void;
}

// Confirmation dialog for an in-app plan change, following the standard
// billing rules: an upgrade applies immediately and the prorated difference
// (new plan minus credit for unused time) is charged now; a downgrade is
// scheduled for the end of the paid period — the current plan stays in force
// until then and nothing is charged or refunded today.
export function PlanChangeDialog({
  preview,
  targetPlan,
  applying,
  renewsOn,
  onConfirm,
  onCancel,
}: PlanChangeDialogProps) {
  const open = preview !== null;
  const amount = preview
    ? formatMinorAmount(preview.amountDue, preview.currency)
    : '';
  const effectiveDate = preview?.effectiveAt
    ? formatPeriodEnd(preview.effectiveAt)
    : 'your renewal date';
  // "Due today" is a one-off prorated figure and never equals the plan's
  // sticker price, which reads as a pricing error unless the recurring price is
  // spelled out right next to it.
  const recurringFrom = renewsOn ? formatPeriodEnd(renewsOn) : null;

  return (
    <Modal
      open={open}
      onClose={onCancel}
      title={
        targetPlan ? `Switch to ${targetPlan.name}` : 'Confirm plan change'
      }
      size="sm"
      footer={
        <>
          <Button variant="secondary" onClick={onCancel} disabled={applying}>
            Cancel
          </Button>
          <Button onClick={onConfirm} disabled={applying}>
            {applying ? 'Applying…' : 'Confirm change'}
          </Button>
        </>
      }
    >
      {preview && (
        <div className="space-y-4 text-sm">
          <div className="flex items-baseline justify-between gap-4">
            <span className="text-muted">Due today</span>
            <span className="text-xl font-bold text-foreground">{amount}</span>
          </div>
          {preview.effectiveImmediately && targetPlan && (
            <div className="flex items-baseline justify-between gap-4 border-t border-border pt-3">
              <span className="text-muted">Then</span>
              <span className="font-semibold text-foreground">
                {targetPlan.price}
                {recurringFrom && (
                  <span className="ml-1 font-normal text-muted">
                    from {recurringFrom}
                  </span>
                )}
              </span>
            </div>
          )}
          <p className="text-muted">
            {preview.effectiveImmediately
              ? 'This upgrade takes effect immediately. Today you pay only the difference for the days left in your current billing period, after crediting the unused time on your old plan — which is why it is less than the plan price. The regular price starts at your next renewal.'
              : `Your current plan stays active until ${effectiveDate} — you keep everything you already paid for. The new plan starts then at its regular price. Nothing is charged or refunded today.`}
          </p>
        </div>
      )}
    </Modal>
  );
}
