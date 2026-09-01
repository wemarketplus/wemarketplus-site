import { useState } from 'react';
import { Plus, Trash2 } from 'lucide-react';
import { Button, Input, Label, Select, Textarea } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import {
  MAX_STEP_DELAY_DAYS,
  MAX_STEPS_PER_SEQUENCE,
  SEQUENCE_ACTION,
  SEQUENCE_ACTION_HINTS,
  SEQUENCE_ACTION_LABELS,
  SEQUENCE_NAME_MAX_LENGTH,
  SEQUENCE_STEP_TITLE_MAX_LENGTH,
  SEQUENCE_TRIGGER,
  SEQUENCE_TRIGGER_LABELS,
  type SequenceAction,
  type SequenceTrigger,
} from '../constants/clAutomationConstants';
import type {
  CreateSequenceRequest,
  SequenceRecord,
  SequenceStepInput,
} from '../types/clAutomationTypes';

interface Props {
  /** Omit to create; supply to edit. */
  sequence?: SequenceRecord;
  isSaving: boolean;
  onClose: () => void;
  onSubmit: (values: CreateSequenceRequest) => Promise<void>;
}

const EMPTY_STEP: SequenceStepInput = {
  delayDays: 0,
  action: SEQUENCE_ACTION.Task,
  title: '',
  body: '',
};

/**
 * Building a sequence: what starts it, then the ordered touches.
 *
 * ── WHY THE DELAY IS "DAYS AFTER THE PREVIOUS STEP" ───────────────────────────
 * Not "days after the lead was lost". The two read the same on a fresh sequence and
 * diverge the moment a step is inserted in the middle: an absolute offset silently
 * re-times every later touch, while a gap pushes them out by exactly the gap the
 * person adding it asked for. The label says so rather than leaving it to be
 * inferred, because getting it wrong is invisible until a campaign fires in the
 * wrong order.
 *
 * ── WHY THERE IS NO EMAIL ACTION ──────────────────────────────────────────────
 * Two actions, and no greyed-out third. The platform has no SMS provider and the
 * mailer has only fixed templates, but the real blocker is not a missing method:
 * sending marketing email to families needs a consent and unsubscribe decision
 * first. A disabled "Email" row would promise that as imminent when it is a product
 * call — the same sold-but-unbuilt pattern this product has been correcting.
 *
 * What the two available actions do is drive the REP to make the touch on schedule.
 * The competitor feature being answered is "nothing slips", not "message the family
 * automatically", so this is a smaller claim honestly kept rather than a larger one
 * half-made.
 */
export function SequenceFormModal({
  sequence,
  isSaving,
  onClose,
  onSubmit,
}: Props) {
  const [name, setName] = useState(sequence?.name ?? '');
  const [description, setDescription] = useState(sequence?.description ?? '');
  const [trigger, setTrigger] = useState<SequenceTrigger>(
    sequence?.trigger ?? SEQUENCE_TRIGGER.ClLeadLost,
  );
  const [steps, setSteps] = useState<SequenceStepInput[]>(
    sequence?.steps?.length
      ? sequence.steps.map((s) => ({
          delayDays: s.delayDays,
          action: s.action,
          title: s.title,
          body: s.body ?? '',
        }))
      : [{ ...EMPTY_STEP }],
  );
  const [error, setError] = useState<string | null>(null);

  const patchStep = (index: number, patch: Partial<SequenceStepInput>) =>
    setSteps((current) =>
      current.map((step, i) => (i === index ? { ...step, ...patch } : step)),
    );

  const addStep = () =>
    setSteps((current) =>
      current.length >= MAX_STEPS_PER_SEQUENCE
        ? current
        : // A new touch defaults to a week out rather than to 0: two steps firing
          // the same hour is never what "add a step" meant, and a 0 that has to be
          // corrected every time is a default working against the user.
          [...current, { ...EMPTY_STEP, delayDays: 7 }],
    );

  const removeStep = (index: number) =>
    setSteps((current) =>
      // Never below one. A sequence with no steps would enrol leads and then do
      // nothing, which is indistinguishable from a broken engine.
      current.length <= 1 ? current : current.filter((_, i) => i !== index),
    );

  const submit = async () => {
    if (!name.trim()) {
      setError('Give the sequence a name.');
      return;
    }
    const blank = steps.findIndex((s) => !s.title.trim());
    if (blank !== -1) {
      setError(`Step ${blank + 1} needs a title — it becomes the task or notification.`);
      return;
    }
    setError(null);
    await onSubmit({
      name: name.trim(),
      ...(description.trim() ? { description: description.trim() } : {}),
      trigger,
      steps: steps.map((s) => ({
        delayDays: s.delayDays,
        action: s.action,
        title: s.title.trim(),
        ...(s.body?.trim() ? { body: s.body.trim() } : {}),
      })),
    });
  };

  return (
    <Modal
      open
      onClose={onClose}
      title={sequence ? `Edit “${sequence.name}”` : 'New follow-up sequence'}
      size="lg"
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={isSaving}>
            {isSaving ? 'Saving…' : sequence ? 'Save changes' : 'Create sequence'}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-5">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="flex flex-col gap-1.5 sm:col-span-2">
            <Label htmlFor="seq-name" required>
              Name
            </Label>
            <Input
              id="seq-name"
              value={name}
              maxLength={SEQUENCE_NAME_MAX_LENGTH}
              onChange={(e) => {
                setName(e.target.value);
                setError(null);
              }}
              placeholder="Re-engage a lost family"
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="seq-trigger" required>
              Starts when
            </Label>
            <Select
              id="seq-trigger"
              value={trigger}
              onChange={(e) => setTrigger(e.target.value as SequenceTrigger)}
            >
              {Object.entries(SEQUENCE_TRIGGER_LABELS).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </Select>
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="seq-desc">Description</Label>
            <Input
              id="seq-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Three touches over two weeks"
            />
          </div>
        </div>

        <div className="flex flex-col gap-3">
          <div className="flex items-baseline justify-between">
            <h3 className="text-[13px] font-semibold uppercase tracking-label text-muted">
              Touches
            </h3>
            <span className="text-[11px] text-muted-soft">
              {steps.length} of {MAX_STEPS_PER_SEQUENCE}
            </span>
          </div>

          {steps.map((step, index) => (
            <div
              key={index}
              className="flex flex-col gap-3 rounded-card border border-border/[0.09] bg-surface p-4"
            >
              <div className="flex items-center justify-between">
                <span className="text-[12px] font-semibold text-foreground">
                  Step {index + 1}
                </span>
                {steps.length > 1 && (
                  <Button
                    variant="secondary"
                    onClick={() => removeStep(index)}
                    aria-label={`Remove step ${index + 1}`}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                )}
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor={`step-delay-${index}`}>
                    {index === 0 ? 'Days after the lead is enrolled' : 'Days after the previous step'}
                  </Label>
                  <Input
                    id={`step-delay-${index}`}
                    type="number"
                    min={0}
                    max={MAX_STEP_DELAY_DAYS}
                    value={String(step.delayDays)}
                    onChange={(e) =>
                      patchStep(index, {
                        delayDays: Math.max(
                          0,
                          Math.min(
                            MAX_STEP_DELAY_DAYS,
                            Number(e.target.value) || 0,
                          ),
                        ),
                      })
                    }
                  />
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor={`step-action-${index}`}>Action</Label>
                  <Select
                    id={`step-action-${index}`}
                    value={step.action}
                    onChange={(e) =>
                      patchStep(index, {
                        action: e.target.value as SequenceAction,
                      })
                    }
                  >
                    {Object.entries(SEQUENCE_ACTION_LABELS).map(
                      ([value, label]) => (
                        <option key={value} value={value}>
                          {label}
                        </option>
                      ),
                    )}
                  </Select>
                  <p className="text-[11px] leading-relaxed text-muted-soft">
                    {SEQUENCE_ACTION_HINTS[step.action]}
                  </p>
                </div>
              </div>

              <div className="flex flex-col gap-1.5">
                <Label htmlFor={`step-title-${index}`} required>
                  What it says
                </Label>
                <Input
                  id={`step-title-${index}`}
                  value={step.title}
                  maxLength={SEQUENCE_STEP_TITLE_MAX_LENGTH}
                  onChange={(e) => {
                    patchStep(index, { title: e.target.value });
                    setError(null);
                  }}
                  placeholder="Call the family to thank them"
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label htmlFor={`step-body-${index}`}>Detail</Label>
                <Textarea
                  id={`step-body-${index}`}
                  rows={2}
                  value={step.body ?? ''}
                  onChange={(e) => patchStep(index, { body: e.target.value })}
                  placeholder="Ask what tipped the decision."
                />
              </div>
            </div>
          ))}

          {steps.length < MAX_STEPS_PER_SEQUENCE && (
            <Button variant="secondary" onClick={addStep}>
              <Plus className="h-4 w-4" /> Add a touch
            </Button>
          )}
        </div>

        {sequence && (
          <p className="text-[12px] leading-relaxed text-muted">
            Leads already part-way through this sequence keep their position — they
            continue from the step they are on, they are not restarted.
          </p>
        )}
        {error && <p className="text-[12px] text-destructive">{error}</p>}
      </div>
    </Modal>
  );
}
