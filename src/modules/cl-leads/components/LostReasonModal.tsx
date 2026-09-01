import { useState } from 'react';
import { Button, Label, Select, Textarea } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import {
  CL_LOST_REASON_DETAIL_MAX_LENGTH,
  CL_LOST_REASON_REQUIRING_DETAIL,
  type ClLostReason,
} from '../constants/clLeadApiConstants';
import { LOST_REASON_OPTIONS } from '../constants/leadsConstants';

interface Props {
  /** Name of the lead being marked lost, for the title. */
  leadName: string;
  isSaving: boolean;
  onCancel: () => void;
  onConfirm: (
    lostReason: ClLostReason,
    lostReasonDetail: string | null,
  ) => Promise<void> | void;
}

/**
 * Asks WHY before a lead is marked lost.
 *
 * ── Why this interrupts the stage dropdown ────────────────────────────────────
 * Every other stage in the pipeline commits straight from the table's status
 * control — one click, one PATCH. `Lost` cannot, because the server refuses a
 * loss with no reason, and a control that fires a request the server rejects
 * would surface as a toast error on a click the user had every reason to think
 * was valid.
 *
 * So the reason is collected BEFORE the request rather than validated after it.
 * That also makes the rule discoverable: the requirement is visible in the moment
 * it applies, instead of being a rule you learn by tripping over it.
 *
 * ── Why cancelling needs no cleanup ───────────────────────────────────────────
 * The table's control renders from the lead record, not from local state, so
 * dismissing this dialog leaves the row showing its real, unchanged stage. There
 * is nothing to roll back because nothing was written.
 *
 * ── Why the free-text box appears rather than always showing ───────────────────
 * It is required for `Other` and meaningless for the rest — a permanently visible
 * "details" box beside a specific reason invites a note nobody reads and makes the
 * one case where text is mandatory look equally optional.
 */
export function LostReasonModal({
  leadName,
  isSaving,
  onCancel,
  onConfirm,
}: Props) {
  const [reason, setReason] = useState<ClLostReason | ''>('');
  const [detail, setDetail] = useState('');
  const [error, setError] = useState<string | null>(null);

  const needsDetail = reason === CL_LOST_REASON_REQUIRING_DETAIL;

  const submit = async () => {
    if (!reason) {
      setError('Choose a reason so this loss can be reported on.');
      return;
    }
    // Mirrors the server's own check (assertClLostReason) including the trim, so
    // whitespace is not accepted as an answer on either side.
    if (needsDetail && !detail.trim()) {
      setError('Add a short note describing what happened.');
      return;
    }
    setError(null);
    await onConfirm(reason, needsDetail ? detail.trim() : null);
  };

  return (
    <Modal
      open
      onClose={onCancel}
      title={`Why was ${leadName} lost?`}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={isSaving}>
            {isSaving ? 'Saving…' : 'Mark as lost'}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        <p className="text-[13px] leading-relaxed text-muted">
          Recorded on the lead and rolled up in the Lost reasons report, so the
          pipeline can show what is actually costing move-ins.
        </p>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="lost-reason" required>
            Reason
          </Label>
          <Select
            id="lost-reason"
            value={reason}
            onChange={(e) => {
              setReason(e.target.value as ClLostReason | '');
              setError(null);
            }}
          >
            <option value="">Select a reason…</option>
            {LOST_REASON_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        </div>
        {needsDetail && (
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="lost-reason-detail" required>
              What happened?
            </Label>
            <Textarea
              id="lost-reason-detail"
              rows={3}
              maxLength={CL_LOST_REASON_DETAIL_MAX_LENGTH}
              value={detail}
              onChange={(e) => {
                setDetail(e.target.value);
                setError(null);
              }}
              placeholder="Family postponed the decision indefinitely"
            />
          </div>
        )}
        {error && <p className="text-[12px] text-destructive">{error}</p>}
      </div>
    </Modal>
  );
}
