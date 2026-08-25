import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { Button, DatePicker, Input, Label, Select, Textarea } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import type { EntitySelectOption } from '@/shared/ui/entity';
import {
  followUpSchema,
  type FollowUpFormValues,
} from '../schema/followUpSchema';

const EMPTY: FollowUpFormValues = {
  prospectId: '',
  title: '',
  dueDate: '',
  cadenceNote: '',
};

interface FollowUpFormModalProps {
  open: boolean;
  isSaving: boolean;
  /** Prospects the marketer can attach a follow-up to. */
  prospectOptions: readonly EntitySelectOption[];
  /** Distinguishes "still loading" from "this tenant has no prospects yet". */
  prospectsLoading: boolean;
  onClose: () => void;
  /** Resolves false when the write failed, so the draft is not thrown away. */
  onSubmit: (values: FollowUpFormValues) => Promise<boolean>;
}

/**
 * Create-only, on purpose. An automation is set up or stood down; "edit" would
 * be a third state to reason about for a record whose whole content is one
 * sentence and one date, and the existing reminder editor on the Activity page
 * already covers changing a task in place.
 *
 * Composed from the shared primitives rather than driven by EntityFormModal
 * because of the prospect picker: EntityFormModal renders an unpopulated lookup
 * as "Loading…" whether the request is in flight or came back empty, and those
 * two mean very different things here. A tenant with no prospects needs to be
 * told to add one — not left watching a picker that will never fill.
 */
export function FollowUpFormModal({
  open,
  isSaving,
  prospectOptions,
  prospectsLoading,
  onClose,
  onSubmit,
}: FollowUpFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<FollowUpFormValues>({
    resolver: zodResolver(followUpSchema),
    defaultValues: EMPTY,
  });

  // Reopening must not resurrect the previous draft: the next follow-up is
  // usually for a different prospect, and a pre-filled name is the kind of thing
  // that gets saved without being read.
  useEffect(() => {
    if (open) reset(EMPTY);
  }, [open, reset]);

  const submit = handleSubmit(async (values) => {
    const ok = await onSubmit(values);
    if (ok) reset(EMPTY);
  });

  const hasProspects = prospectOptions.length > 0;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="New follow-up"
      size="lg"
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={isSaving || !hasProspects}>
            {isSaving ? 'Saving…' : 'Schedule follow-up'}
          </Button>
        </>
      }
    >
      <form autoComplete="off" onSubmit={submit} className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <Label htmlFor="follow-up-prospect">Prospect</Label>
          <Select
            id="follow-up-prospect"
            disabled={!hasProspects}
            {...register('prospectId')}
          >
            <option value="">
              {prospectsLoading
                ? 'Loading prospects…'
                : hasProspects
                  ? 'Select a prospect…'
                  : 'No prospects yet — add one first'}
            </option>
            {prospectOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </Select>
          {errors.prospectId?.message && (
            <p className="mt-1 text-[12px] text-destructive">
              {errors.prospectId.message}
            </p>
          )}
        </div>

        <div className="sm:col-span-2">
          <Label htmlFor="follow-up-title">What to do</Label>
          <Input
            id="follow-up-title"
            placeholder="Call the DON about the eligibility packet"
            {...register('title')}
          />
          {errors.title?.message && (
            <p className="mt-1 text-[12px] text-destructive">
              {errors.title.message}
            </p>
          )}
        </div>

        <div>
          <Label htmlFor="follow-up-due">Due date</Label>
          <DatePicker id="follow-up-due" {...register('dueDate')} />
          {errors.dueDate?.message && (
            <p className="mt-1 text-[12px] text-destructive">
              {errors.dueDate.message}
            </p>
          )}
        </div>

        <div className="sm:col-span-2">
          <Label htmlFor="follow-up-cadence">Cadence note (optional)</Label>
          <Textarea
            id="follow-up-cadence"
            rows={3}
            placeholder="Fortnightly until the face-to-face is booked"
            {...register('cadenceNote')}
          />
          {/* Says plainly that this does not recur by itself. A field called
              "cadence" that quietly failed to reschedule anything would be the
              exact thing this feature promises not to do. */}
          <p className="mt-1 text-[12px] text-muted-soft">
            A note to yourself about how often to circle back. It does not
            reschedule automatically — set the next follow-up when you close this
            one.
          </p>
        </div>
      </form>
    </Modal>
  );
}
