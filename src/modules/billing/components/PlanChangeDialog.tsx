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
  // Upgrade vs downgrade drives the label, the copy and whether there is
  // anything to pay, so resolve it once rather than re-testing the flag.
  const upgrading = preview?.effectiveImmediately ?? false;

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
          {/*
            `ghost`, not `secondary` — the same pairing ConfirmDialog uses, so
            every confirm footer in the app has one filled action and one quiet
            way out. Cancel does not need a border to be findable next to a
            solid green pill, and giving it one made the footer read as two
            equal choices.
          */}
          <Button variant="ghost" onClick={onCancel} disabled={applying}>
            Cancel
          </Button>
          {/*
            Names the action rather than acknowledging the question — the rule
            ConfirmDialog documents. "Confirm change" was also the one label
            that could not tell the two outcomes apart: an upgrade charges a card
            right now, a downgrade only books something for the renewal date.
          */}
          <Button onClick={onConfirm} disabled={applying}>
            {applying
              ? 'Applying…'
              : upgrading
                ? 'Upgrade now'
                : 'Schedule downgrade'}
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
          {upgrading && targetPlan && (
            /*
              The rule was `border-border` — the token at FULL alpha, which on
              the light palette is #11201a, a near-black 1px line. Inside a panel
              whose own header and footer rules are drawn at 7% it read as a
              heavy black bar splitting the two figures. Matches them now.
            */
            <div className="flex items-baseline justify-between gap-4 border-t border-border/[0.07] pt-3">
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
          {/*
            One short paragraph, not three sentences of billing policy. The old
            upgrade copy closed with "The regular price starts at your next
            renewal", which the "Then … from <date>" row above already states —
            and re-stating a number in prose is how the two drift apart. What
            prose is actually needed for is the one thing the figures cannot
            explain: why "Due today" is LESS than the plan's sticker price.
          */}
          <p className="text-muted">
            {upgrading
              ? 'Your new plan starts right away. Today covers only the days left in this billing period, less credit for the unused time on your old plan — which is why it is below the full price.'
              : `Nothing is charged or refunded today. Your current plan stays active until ${effectiveDate}, and the new one starts then at its regular price.`}
          </p>
        </div>
      )}
    </Modal>
  );
}
