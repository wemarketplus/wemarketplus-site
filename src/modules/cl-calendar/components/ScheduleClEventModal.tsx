import { useEffect, useMemo } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { Controller, useForm } from 'react-hook-form';
import {
  LocationField,
  toLocationValue,
  type LocationValue,
} from '@/modules/geocoding';
import { useTenantStaffOptions } from '@/modules/users';
import {
  Button,
  Input,
  Label,
  ListboxSelect,
  Select,
  Textarea,
} from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import { cn } from '@/shared/utils/cn';
import { nowLocalDateTime, todayLocalDate } from '@/shared/utils/dateFormatter';
import { CL_SCHEDULE_CHOICES } from '../constants/clCalendarConstants';
import { clSeedTourWhen } from '../utils/clCalendarUtils';
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

/**
 * A tour needs a clock; a visit is an all-day record.
 *
 * The clock comes from `clSeedTourWhen` rather than a flat 10:00 so that
 * clicking TODAY after 10am does not open the form on a time the past-date rule
 * rejects on sight.
 */
const defaults = (dayKey: string): ClScheduleFormValues => ({
  kind: 'tour',
  when: clSeedTourWhen(dayKey),
  leadId: '',
  guideUserId: '',
  durationMin: '60',
  fromLocation: '',
  fromLat: undefined,
  fromLng: undefined,
  toLocation: '',
  toLat: undefined,
  toLng: undefined,
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
    control,
    formState: { errors },
  } = useForm<ClScheduleFormValues>({
    resolver: zodResolver(clScheduleSchema),
    defaultValues: defaults(dayKey),
  });

  const staff = useTenantStaffOptions(open);
  const kind = watch('kind');
  const isTour = kind === 'tour';

  /**
   * The two long pickers' options with their "none" row PREPENDED.
   *
   * A native <select> carried this as an `<option value="">`, and a listbox's
   * `placeholder` is not a substitute: the placeholder only renders while the
   * value matches nothing, so with it alone a source picked by mistake could
   * never be un-picked. Both fields are optional on the wire (`referralSourceId`
   * / `leadId` are omitted when blank), so "not linked" has to stay reachable as
   * a real choice.
   */
  const sourceChoices = useMemo(
    () => [{ value: '', label: '— Not linked —' }, ...referralSourceOptions],
    [referralSourceOptions],
  );
  const leadChoices = useMemo(
    () => [{ value: '', label: '— No lead —' }, ...leadOptions],
    [leadOptions],
  );

  /**
   * The tour's From/To, assembled for the picker and split back into the flat
   * fields on return — the same `watch`/`setValue` pairing the Book-tour form
   * uses, because <LocationField> is a dialog rather than an input `register`
   * could bind to.
   */
  const endpoint = (side: 'from' | 'to'): LocationValue =>
    side === 'from'
      ? toLocationValue(watch('fromLocation'), watch('fromLat'), watch('fromLng'))
      : toLocationValue(watch('toLocation'), watch('toLat'), watch('toLng'));

  const setEndpoint = (side: 'from' | 'to') => (next: LocationValue) => {
    // All three together, clears included: a label whose pin belongs to a place
    // it no longer names is worse than no location at all.
    setValue(`${side}Location`, next.label, { shouldDirty: true });
    setValue(`${side}Lat`, next.coords?.lat, { shouldDirty: true });
    setValue(`${side}Lng`, next.coords?.lng, { shouldDirty: true });
  };

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
    setValue('when', next === 'tour' ? clSeedTourWhen(day) : day);
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
          <Button variant="secondary" onClick={onClose} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={isSaving}>
            {isSaving ? 'Saving…' : 'Schedule'}
          </Button>
        </>
      }
    >
      <form autoComplete="off" onSubmit={submit} className="space-y-4">
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
                  'rounded-md border px-3 py-2.5 text-left transition-colors',
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
              /**
               * Greys out everything before now in the picker itself — at the
               * MINUTE for a tour, at the DAY for a visit, matching the
               * precision each field carries and the two branches of the
               * schema's rule. Called at render, not module load, so a modal
               * left open across midnight does not still offer yesterday.
               *
               * The floor is the first of two layers: a typed value still gets
               * through it (and this modal submits via an onClick `type="button"`,
               * so native constraint validation never runs), which is what the
               * schema rule is for.
               */
              min={isTour ? nowLocalDateTime() : todayLocalDate()}
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
              {/* The other 100-item list in this modal, bounded for exactly the
                  same reason as Referral source below. Fixed in the same pass
                  because it is the same defect one branch away — the Staff
                  picker beside it is a short tenant list and stays native. */}
              <div className="sm:col-span-2">
                <Label htmlFor="cs-lead">Prospect</Label>
                <Controller
                  control={control}
                  name="leadId"
                  render={({ field }) => (
                    <ListboxSelect
                      id="cs-lead"
                      value={field.value ?? ''}
                      onChange={field.onChange}
                      onBlur={field.onBlur}
                      options={leadChoices}
                      placeholder="— No lead —"
                    />
                  )}
                />
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
              {/* Where the tour starts and ends. The map picker searches, takes a
                  tap, or reads the device's own position — so a marketer already
                  standing at the pickup point can set it without typing an
                  address. */}
              <LocationField
                id="cs-from"
                label="From"
                value={endpoint('from')}
                onChange={setEndpoint('from')}
                placeholder="Pickup point — hospital, home…"
              />
              <LocationField
                id="cs-to"
                label="To"
                value={endpoint('to')}
                onChange={setEndpoint('to')}
                placeholder="Community being toured"
              />
            </>
          )}

          {!isTour && (
            <>
              {/* A BOUNDED list, not a native <select>.
                  This is the tenant's whole referral-source book —
                  CL_CALENDAR_FETCH_LIMIT is 100, each labelled
                  "name — organization" — and a native select's popup is drawn by
                  the browser at whatever height its option count implies, which
                  for 100 rows is a list taller than the viewport that Chrome then
                  places over the rest of the modal. `size`, `max-height` and
                  `overflow` cannot reach it; only not letting the browser draw it
                  can, which is what <ListboxSelect> exists for (see the note
                  there — this is the same defect as the 51-state pickers, and the
                  reason it needs `Controller` is that the trigger is a <button>,
                  not a form control `register` can ref). Capped at 264px with its
                  own scrollbar. */}
              <div className="sm:col-span-2">
                <Label htmlFor="cs-source">Referral source</Label>
                <Controller
                  control={control}
                  name="referralSourceId"
                  render={({ field }) => (
                    <ListboxSelect
                      id="cs-source"
                      value={field.value ?? ''}
                      onChange={field.onChange}
                      onBlur={field.onBlur}
                      options={sourceChoices}
                      placeholder="— Not linked —"
                    />
                  )}
                />
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
