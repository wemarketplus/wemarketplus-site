import { useEffect, useState } from 'react';
import type { ProspectLostReason } from '@/modules/prospects/types/prospectsTypes';
import { Button, Label, Select, Textarea } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import {
  LOST_REASON_DETAIL_MAX_LENGTH,
  LOST_REASON_OPTIONS,
  LOST_REASON_REQUIRING_DETAIL,
} from '../constants/pipelineConstants';

interface LostReasonModalProps {
  open: boolean;
  isSaving: boolean;
  /** Name of the card being closed out, so the prompt names the patient. */
  cardTitle: string;
  onCancel: () => void;
  /** Resolves false when the move failed, in which case the dialog stays open. */
  onConfirm: (
    lostReason: ProspectLostReason,
    lostReasonDetail?: string,
  ) => Promise<boolean>;
}

/**
 * Collects WHY an opportunity was lost before the move is sent.
 *
 * This is not a nicety — the backend now rejects a move into `lost` without a
 * reason (ProspectsService.assertLostReason), so without this dialog dragging a
 * card to the Lost column would simply fail. It exists because a lost referral
 * with no recorded reason is unusable for re-engagement, which is the one thing
 * every competitor builds on this data.
 *
 * `other` additionally requires free text, enforced here as well as server-side —
 * otherwise "other" silently becomes the same missing information.
 */
export function LostReasonModal({
  open,
  isSaving,
  cardTitle,
  onCancel,
  onConfirm,
}: LostReasonModalProps) {
  const [reason, setReason] = useState<ProspectLostReason | ''>('');
  const [detail, setDetail] = useState('');
  const [touched, setTouched] = useState(false);

  // Reset on every open so a previous card's reason is never pre-filled onto the
  // next one — a wrong reason is worse than no reason.
  useEffect(() => {
    if (!open) return;
    setReason('');
    setDetail('');
    setTouched(false);
  }, [open]);

  const needsDetail = reason === LOST_REASON_REQUIRING_DETAIL;
  const missingReason = reason === '';
  const missingDetail = needsDetail && detail.trim() === '';
  const canSubmit = !missingReason && !missingDetail && !isSaving;

  const submit = () => {
    setTouched(true);
    if (missingReason || missingDetail) return;
    void onConfirm(
      reason as ProspectLostReason,
      needsDetail ? detail.trim() : undefined,
    );
  };

  return (
    <Modal
      open={open}
      onClose={onCancel}
      title="Why was this lost?"
      size="md"
      footer={
        <>
          <Button variant="secondary" onClick={onCancel} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={!canSubmit}>
            {isSaving ? 'Saving…' : 'Mark as lost'}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <p className="text-sm text-muted">
          Closing out <span className="text-foreground">{cardTitle}</span>. A reason
          is required so this referral can be reported on and re-engaged later.
        </p>

        <div className="space-y-1.5">
          <Label htmlFor="lost-reason">Reason</Label>
          <Select
            id="lost-reason"
            value={reason}
            onChange={(event) =>
              setReason(event.target.value as ProspectLostReason | '')
            }
          >
            <option value="">Select a reason…</option>
            {LOST_REASON_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </Select>
          {touched && missingReason && (
            <p className="text-xs text-destructive">Pick a reason to continue.</p>
          )}
        </div>

        {needsDetail && (
          <div className="space-y-1.5">
            <Label htmlFor="lost-reason-detail">What happened?</Label>
            <Textarea
              id="lost-reason-detail"
              value={detail}
              maxLength={LOST_REASON_DETAIL_MAX_LENGTH}
              placeholder="e.g. family chose in-home care after the assessment"
              onChange={(event) => setDetail(event.target.value)}
            />
            {touched && missingDetail && (
              <p className="text-xs text-destructive">
                A short description is required when the reason is “other”.
              </p>
            )}
          </div>
        )}
      </div>
    </Modal>
  );
}
