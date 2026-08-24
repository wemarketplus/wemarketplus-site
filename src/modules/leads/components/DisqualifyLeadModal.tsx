import { useState } from 'react';
import { Button, Label, Select } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import { LEAD_DISQUALIFY_OPTIONS } from '../constants/leadsConstants';
import { LeadDisqualifyReason, type LeadRecord } from '../types/leadsTypes';

interface DisqualifyLeadModalProps {
  lead: LeadRecord | null;
  isSaving: boolean;
  onClose: () => void;
  onConfirm: (reason: LeadDisqualifyReason) => void;
}

/** The backend requires a reason, so this is a modal rather than a bare button. */
export function DisqualifyLeadModal({
  lead,
  isSaving,
  onClose,
  onConfirm,
}: DisqualifyLeadModalProps) {
  const [reason, setReason] = useState<LeadDisqualifyReason>(
    LeadDisqualifyReason.NotEligible,
  );

  return (
    <Modal
      open={lead !== null}
      onClose={onClose}
      title="Disqualify lead"
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={() => onConfirm(reason)} disabled={isSaving}>
            {isSaving ? 'Saving…' : 'Disqualify'}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <p className="text-sm text-muted">
          {lead?.patientName ?? 'This referral'} will be closed and removed from
          the intake queue. This cannot be undone from the UI.
        </p>
        <div>
          <Label htmlFor="dq-reason">Reason</Label>
          <Select
            id="dq-reason"
            value={reason}
            onChange={(event) =>
              setReason(event.target.value as LeadDisqualifyReason)
            }
          >
            {LEAD_DISQUALIFY_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </Select>
        </div>
      </div>
    </Modal>
  );
}
