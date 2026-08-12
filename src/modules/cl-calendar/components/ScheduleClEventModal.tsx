import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { useTenantStaffOptions } from '@/modules/users';
import { Button, Input, Label, Select, Textarea } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import { cn } from '@/shared/utils/cn';
import { CL_SCHEDULE_CHOICES } from '../constants/clCalendarConstants';
import {
  clScheduleSchema,
  type ClScheduleFormValues,
} from '../schema/clCalendarSchema';

interface ScheduleClEventModalProps {
  open: boolean;
  /** `YYYY-MM-DD` the user clicked. Seeds the date input. */
  dayKey: string;
  isSaving: boolean;
  leadOptions: ReadonlyArray<{ value: string; label: string }>;
  referralSourceOptions: ReadonlyArray<{ value: string; label: string }>;
  onClose: () => void;
  onSubmit: (values: ClScheduleFormValues) => Promise<boolean>;
}

/** A tour needs a clock; a visit is an all-day record. */
const defaults = (dayKey: string): ClScheduleFormValues => ({
  kind: 'tour',
  when: dayKey ? `${dayKey}T10:00` : '',
  leadId: '',
  guideUserId: '',
  durationMin: '60',
  locationName: '',
  contactName: '',
  referralSourceId: '',
  notes: '',
});

/**
 * "You can schedule a tour, a facility visit, or even a physician lunch
 * directly."
 *
 * The kind is picked FIRST, as three cards rather than a dropdown, because it
 * changes which fields matter — and then only that kind's fields are shown. A
 * single flat form with every field visible would ask a marketer booking a lunch
 * which family is touring.
 */
export function ScheduleClEventModal({
  open,
  dayKey,
  isSaving,
  leadOptions,
  referralSourceOptions,
  onClose,
  onSubmit,
}: ScheduleClEventModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    watch,
    setValue,
    formState: { errors },
  } = useForm<ClScheduleFormValues>({
    resolver: zodResolver(clScheduleSchema),
    defaultValues: defaults(dayKey),
  });

  const staff = useTenantStaffOptions(open);
  const kind = watch('kind');
  const isTour = kind === 'tour';

  useEffect(() => {
    if (open) reset(defaults(dayKey));
  }, [open, dayKey, reset]);

  /**
   * The `when` input swaps between `datetime-local` and `date`, and the two do
   * not accept each other's values — a `date` input silently rejects
   * "2026-08-11T10:00" and renders blank. So the value is rewritten whenever the
   * kind changes, preserving the day the user originally clicked.
   */
  const changeKind = (next: ClScheduleFormValues['kind']) => {
    const day = (watch('when') || dayKey).slice(0, 10);
    setValue('kind', next);
    setValue('when', next === 'tour' ? `${day}T10:00` : day);
  };

  const submit = handleSubmit(async (values) => {
    const ok = await onSubmit(values);
    if (ok) {
      reset(defaults(dayKey));
      onClose();
    }
  });

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Schedule"
      size="md"
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={isSaving}>
            {isSaving ? 'Saving…' : 'Schedule'}
          </Button>
        </>
      }
    >
      <form onSubmit={submit} className="space-y-4">
        <div>
          <Label>What are you scheduling?</Label>
          <div
            role="radiogroup"
            aria-label="What are you scheduling?"
            className="mt-1.5 grid grid-cols-1 gap-2 sm:grid-cols-3"
          >
            {CL_SCHEDULE_CHOICES.map((choice) => (
              <button
                key={choice.value}
                type="button"
                role="radio"
                aria-checked={kind === choice.value}
                onClick={() =>
                  changeKind(choice.value as ClScheduleFormValues['kind'])
                }
                className={cn(
                  'rounded-[10px] border px-3 py-2.5 text-left transition-colors',
                  kind === choice.value
                    ? 'border-primary/50 bg-primary/[0.07]'
                    : 'border-border/[0.12] hover:border-border/25',
                )}
              >
                <span className="block text-[13px] font-bold text-foreground">
                  {choice.label}
                </span>
                <span className="mt-0.5 block text-[11px] leading-snug text-muted-soft">
                  {choice.hint}
                </span>
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className={isTour ? '' : 'sm:col-span-2'}>
            <Label htmlFor="cs-when">{isTour ? 'Date & time' : 'Date'}</Label>
            <Input
              id="cs-when"
              type={isTour ? 'datetime-local' : 'date'}
              {...register('when')}
            />
            {errors.when && (
              <p className="mt-1 text-[12px] text-destructive">
                {errors.when.message}
              </p>
            )}
          </div>

          {isTour && (
            <>
              <div>
                <Label htmlFor="cs-duration">Duration</Label>
                <Select id="cs-duration" {...register('durationMin')}>
                  <option value="30">30 min</option>
                  <option value="45">45 min</option>
                  <option value="60">1 hour</option>
                  <option value="90">1.5 hours</option>
                </Select>
              </div>
              <div className="sm:col-span-2">
                <Label htmlFor="cs-lead">Prospect</Label>
                <Select id="cs-lead" {...register('leadId')}>
                  <option value="">— No lead —</option>
                  {leadOptions.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </Select>
              </div>
              <div className="sm:col-span-2">
                <Label htmlFor="cs-guide">Staff member giving the tour</Label>
                <Select id="cs-guide" {...register('guideUserId')}>
                  <option value="">— Unassigned —</option>
                  {staff.options.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </Select>
                {!staff.isFullDirectory && (
                  <p className="mt-1 text-[11px] text-muted-soft">
                    You can assign yourself; an administrator can assign anyone.
                  </p>
                )}
              </div>
            </>
          )}

          {!isTour && (
            <>
              <div className="sm:col-span-2">
                <Label htmlFor="cs-source">Referral source</Label>
                <Select id="cs-source" {...register('referralSourceId')}>
                  <option value="">— Not linked —</option>
                  {referralSourceOptions.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </Select>
              </div>
              <div>
                <Label htmlFor="cs-location">Facility / organization</Label>
                <Input
                  id="cs-location"
                  placeholder="Dallas Medical Group"
                  {...register('locationName')}
                />
                {errors.locationName && (
                  <p className="mt-1 text-[12px] text-destructive">
                    {errors.locationName.message}
                  </p>
                )}
              </div>
              <div>
                <Label htmlFor="cs-contact">Contact</Label>
                <Input
                  id="cs-contact"
                  placeholder="Dr. Amanda Chen"
                  {...register('contactName')}
                />
              </div>
            </>
          )}

          <div className="sm:col-span-2">
            <Label htmlFor="cs-notes">Notes</Label>
            <Textarea
              id="cs-notes"
              placeholder="What is planned…"
              {...register('notes')}
            />
          </div>
        </div>
      </form>
    </Modal>
  );
}
