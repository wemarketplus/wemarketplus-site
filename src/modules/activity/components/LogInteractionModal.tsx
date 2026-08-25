import { useState } from 'react';
import { Button, Checkbox, DatePicker, Input, Label, Select, Textarea } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import {
  ACTIVITY_TYPE_OPTIONS,
  ACTIVITY_TYPE_REQUIRING_DETAIL,
  ActivityType,
} from '@/shared/constants/activityTypeConstants';
import type { CreateNoteRequest } from '../types/activityTypes';

interface LogInteractionModalProps {
  open: boolean;
  isSaving: boolean;
  title: string;
  /** Exactly one of these is supplied by the caller — it is the note's target. */
  target: Pick<
    CreateNoteRequest,
    'prospectId' | 'referralSourceId' | 'contactId'
  >;
  /** Shown when the note is about a patient, hidden for an account. */
  showFamilySensitive?: boolean;
  /**
   * Narrows "what happened" to a subset of the shared enum. The Family
   * Communication screen passes the family channels: this enum is shared with
   * marketing, so the default list offers a nurse a Lunch & Learn and a Gift
   * Delivery as ways of describing a call to a patient's daughter — and the log
   * filters on the family set, so an entry filed under a marketing type would not
   * appear in it. Omit for the full list.
   */
  activityTypeOptions?: ReadonlyArray<{ value: string; label: string }>;
  /** Overrides the default "what happened". */
  defaultActivityType?: ActivityType;
  onClose: () => void;
  onSubmit: (body: CreateNoteRequest) => Promise<boolean>;
}

const EMPTY = {
  activityType: ActivityType.FacilityOfficeVisit as ActivityType,
  activityTypeOther: '',
  summary: '',
  nextStep: '',
  followUpDate: '',
  isFamilySensitive: false,
};

/**
 * Logs one interaction against a prospect, account or contact.
 *
 * This is how a marketer records a drop-off or a call WITHOUT leaving the record
 * they are looking at, which is the whole requirement — the alternative was
 * navigating to Notes and re-finding the facility by name.
 *
 * Two rules are mirrored from the backend rather than hoped for:
 *   - `other` requires free text (NotesService 400s without it), so the field
 *     appears and is required exactly when that value is chosen.
 *   - a follow-up date creates a Reminder server-side, so the helper text states
 *     that as a fact the user can rely on.
 */
export function LogInteractionModal({
  open,
  isSaving,
  title,
  target,
  showFamilySensitive = false,
  activityTypeOptions = ACTIVITY_TYPE_OPTIONS,
  defaultActivityType,
  onClose,
  onSubmit,
}: LogInteractionModalProps) {
  const blank = defaultActivityType
    ? { ...EMPTY, activityType: defaultActivityType }
    : EMPTY;
  const [values, setValues] = useState(blank);
  const [error, setError] = useState<string | null>(null);

  const needsDetail = values.activityType === ACTIVITY_TYPE_REQUIRING_DETAIL;

  const set = <K extends keyof typeof EMPTY>(
    key: K,
    value: (typeof EMPTY)[K],
  ) => setValues((v) => ({ ...v, [key]: value }));

  const close = () => {
    setValues(blank);
    setError(null);
    onClose();
  };

  const submit = async () => {
    if (!values.summary.trim()) {
      setError('Describe what happened.');
      return;
    }
    if (needsDetail && !values.activityTypeOther.trim()) {
      setError('Describe the interaction type.');
      return;
    }
    setError(null);
    const ok = await onSubmit({
      ...target,
      summary: values.summary.trim(),
      activityType: values.activityType,
      // Only sent for `other`; sending it otherwise would persist dead text.
      activityTypeOther: needsDetail
        ? values.activityTypeOther.trim()
        : undefined,
      nextStep: values.nextStep.trim() || undefined,
      followUpDate: values.followUpDate || undefined,
      isFamilySensitive: showFamilySensitive
        ? values.isFamilySensitive
        : undefined,
    });
    if (ok) close();
  };

  return (
    <Modal
      open={open}
      onClose={close}
      title={title}
      size="lg"
      footer={
        <>
          <Button variant="secondary" onClick={close} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={isSaving}>
            {isSaving ? 'Saving…' : 'Log interaction'}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div>
          <Label htmlFor="li-type">What happened</Label>
          <Select
            id="li-type"
            value={values.activityType}
            onChange={(e) => set('activityType', e.target.value as ActivityType)}
          >
            {activityTypeOptions.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        </div>

        {needsDetail && (
          <div>
            <Label htmlFor="li-other">Describe the interaction type</Label>
            <Input
              id="li-other"
              value={values.activityTypeOther}
              onChange={(e) => set('activityTypeOther', e.target.value)}
              maxLength={200}
            />
          </div>
        )}

        <div>
          <Label htmlFor="li-summary">Notes</Label>
          <Textarea
            id="li-summary"
            value={values.summary}
            onChange={(e) => set('summary', e.target.value)}
            placeholder="Who you spoke to and what was discussed"
          />
        </div>

        <div>
          <Label htmlFor="li-next">Next step</Label>
          <Input
            id="li-next"
            value={values.nextStep}
            onChange={(e) => set('nextStep', e.target.value)}
          />
        </div>

        <div>
          <Label htmlFor="li-follow">Follow up on</Label>
          <DatePicker
            id="li-follow"
            value={values.followUpDate}
            onChange={(e) => set('followUpDate', e.target.value)}
          />
          <p className="mt-1 text-[11px] text-muted-soft">
            Setting a date creates a reminder in your daily tasks.
          </p>
        </div>

        {showFamilySensitive && (
          <label className="flex items-start gap-2 text-sm text-foreground">
            <Checkbox
              className="mt-1"
              checked={values.isFamilySensitive}
              onChange={(e) => set('isFamilySensitive', e.target.checked)}
            />
            <span>
              Team only — not for the family
              <span className="block text-[11px] text-muted-soft">
                Flags the note as family-sensitive. It stays visible to everyone
                on your team; this marks it so it is never surfaced to a family
                member.
              </span>
            </span>
          </label>
        )}

        {error && <p className="text-[12px] text-destructive">{error}</p>}
      </div>
    </Modal>
  );
}
