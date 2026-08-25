import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import {
  LocationField,
  toLocationValue,
  type LocationValue,
} from '@/modules/geocoding';
import { Button, Input, Label, Select, Textarea } from '@/shared/ui/core';
import { nowLocalDateTime } from '@/shared/utils/dateFormatter';
import { Modal } from '@/shared/ui/feedback';
import type { EntitySelectOption } from '@/shared/ui/entity';
import { CL_TOUR_STATUS } from '../constants/clToursApiConstants';
import { TOUR_DURATION_OPTIONS, TOUR_STATUS_OPTIONS } from '../constants/clToursConstants';
import { tourSchema, type TourFormValues } from '../schema/clTourSchema';
import { toTourFormValues } from '../utils/clToursUtils';
import type { ClTourRecord } from '../types/clToursApiTypes';

const EMPTY: TourFormValues = {
  leadId: '',
  guideUserId: '',
  scheduledAt: '',
  status: CL_TOUR_STATUS.Scheduled,
  durationMin: '60',
  fromLocation: '',
  fromLat: undefined,
  fromLng: undefined,
  toLocation: '',
  toLat: undefined,
  toLng: undefined,
  outcome: '',
  notes: '',
};

interface TourFormModalProps {
  open: boolean;
  isSaving: boolean;
  editing?: ClTourRecord | null;
  leadOptions: readonly EntitySelectOption[];
  /** Tenant users who could give the tour. Undefined while still loading. */
  guideOptions: readonly EntitySelectOption[] | undefined;
  onClose: () => void;
  onSubmit: (values: TourFormValues) => Promise<boolean>;
}

// Book/edit-tour modal. Not purely field-driven because it needs a lead picker
// populated from live data, so it owns its react-hook-form instance directly.
export function TourFormModal({
  open,
  isSaving,
  editing,
  leadOptions,
  guideOptions,
  onClose,
  onSubmit,
}: TourFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    setValue,
    setError,
    watch,
    formState: { errors },
  } = useForm<TourFormValues>({
    resolver: zodResolver(tourSchema),
    defaultValues: EMPTY,
  });

  /**
   * The two endpoints, assembled from the flat form fields for the picker and
   * split back out when it returns.
   *
   * `watch` + `setValue` rather than a registered input, because the value is a
   * place and not a string: <LocationField> is read-only text plus a map dialog,
   * so there is no change event for `register` to bind to. Same shape the
   * appointment form uses.
   */
  const endpoint = (side: 'from' | 'to'): LocationValue =>
    side === 'from'
      ? toLocationValue(watch('fromLocation'), watch('fromLat'), watch('fromLng'))
      : toLocationValue(watch('toLocation'), watch('toLat'), watch('toLng'));

  const setEndpoint = (side: 'from' | 'to') => (next: LocationValue) => {
    // Label and coordinates move TOGETHER — including on a clear, where all
    // three go blank at once. A label left behind with the old pin still
    // attached is a row that names one place and points at another.
    setValue(`${side}Location`, next.label, { shouldDirty: true });
    setValue(`${side}Lat`, next.coords?.lat, { shouldDirty: true });
    setValue(`${side}Lng`, next.coords?.lng, { shouldDirty: true });
  };

  useEffect(() => {
    if (!open) return;
    reset(editing ? toTourFormValues(editing) : EMPTY);
  }, [open, editing, reset]);

  const close = () => {
    reset(EMPTY);
    onClose();
  };

  const submit = handleSubmit(async (values) => {
    /**
     * A tour cannot be booked into a time that has already passed.
     *
     * Second of the two layers of the same rule: `min={nowLocalDateTime()}` on
     * the input below greys out earlier days and marks an earlier time
     * `:invalid`, but neither stops a TYPED value — and this modal's submit is a
     * `type="button"` with an onClick, so native constraint validation never
     * runs on it at all. Without this guard the floor was decorative.
     *
     * Compared as STRINGS, both "yyyy-MM-ddTHH:mm": fixed-width and zero-padded,
     * so `<` is a correct chronological compare down to the minute, and the
     * same-day-earlier-time case (09:00 booked at 14:00) is caught — which is
     * the half a date-only floor cannot express. No Date parsing, so no
     * timezone conversion to get wrong.
     *
     * Only on create, or on edit when the user actually CHANGED the time —
     * identical to the task due-date and lead follow-up rules. A tour that has
     * simply gone by has to stay editable: recording its outcome, or marking it
     * a no-show, is exactly what happens AFTER it was due, and must not be
     * blocked by a timestamp nobody touched.
     */
    const changedWhen = !editing || values.scheduledAt !== toTourFormValues(editing).scheduledAt;
    if (changedWhen && values.scheduledAt && values.scheduledAt < nowLocalDateTime()) {
      setError('scheduledAt', { message: 'A tour cannot be scheduled in the past.' });
      return;
    }
    const ok = await onSubmit(values);
    if (ok) reset(EMPTY);
  });

  return (
    <Modal
      open={open}
      onClose={close}
      title={editing ? 'Edit tour' : 'Book tour'}
      size="md"
      footer={
        <>
          <Button variant="secondary" onClick={close} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={isSaving}>
            {isSaving ? 'Saving…' : editing ? 'Save changes' : 'Book tour'}
          </Button>
        </>
      }
    >
      <form autoComplete="off" onSubmit={submit} className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <Label htmlFor="tf-lead">Lead</Label>
          <Select id="tf-lead" {...register('leadId')}>
            <option value="">— No lead —</option>
            {leadOptions.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        </div>
        {/* Who is giving the tour — the guide's fourth thing to pick, and the
            reason cl_tours.guideUserId existed with nothing writing it. Disabled
            while the user list loads rather than rendering an empty picker that
            looks like "nobody works here". */}
        <div className="sm:col-span-2">
          <Label htmlFor="tf-guide">Tour guide</Label>
          <Select
            id="tf-guide"
            disabled={guideOptions === undefined}
            {...register('guideUserId')}
          >
            <option value="">
              {guideOptions === undefined ? 'Loading…' : '— Unassigned —'}
            </option>
            {(guideOptions ?? []).map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        </div>
        {/* THE ONLY REQUIRED FIELD ON THIS FORM. tourSchema makes scheduledAt
            `.min(1)` and CreateClTourDto is the only non-@IsOptional key, so it
            is the only one that earns a `*`: Lead and Tour guide are both
            explicitly optional ("— Unassigned —" is a real state), and Status /
            Duration are schema-required but pre-filled with no empty option, so
            marking them would be noise. */}
        <div className="sm:col-span-2">
          <Label htmlFor="tf-when" required>
            Date &amp; time
          </Label>
          <Input
            id="tf-when"
            type="datetime-local"
            aria-required
            // Floors the picker at this minute. Called at RENDER, not module
            // load, so a modal left open across midnight does not still offer
            // yesterday — same reasoning as `min: todayLocalDate` being passed
            // as the function in the entity field descriptors.
            min={nowLocalDateTime()}
            {...register('scheduledAt')}
          />
          {errors.scheduledAt && (
            <p className="mt-1 text-[12px] text-destructive">{errors.scheduledAt.message}</p>
          )}
        </div>
        <div>
          <Label htmlFor="tf-status">Status</Label>
          <Select id="tf-status" {...register('status')}>
            {TOUR_STATUS_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="tf-duration">Duration</Label>
          <Select id="tf-duration" {...register('durationMin')}>
            {TOUR_DURATION_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        </div>
        {/* WHERE the tour happens — the two questions a guide asks the morning
            of: am I collecting them from somewhere, and which community am I
            showing. Each opens the shared map picker, so a place can be
            searched, tapped on the map, or taken from the device's own location
            ("Use my location") when the marketer is standing in it. */}
        <LocationField
          id="tf-from"
          label="From"
          value={endpoint('from')}
          onChange={setEndpoint('from')}
          placeholder="Pickup point — hospital, home…"
        />
        <LocationField
          id="tf-to"
          label="To"
          value={endpoint('to')}
          onChange={setEndpoint('to')}
          placeholder="Community being toured"
        />
        <div className="sm:col-span-2">
          <Label htmlFor="tf-outcome">Outcome</Label>
          <Input id="tf-outcome" placeholder="Toured, deposit taken…" {...register('outcome')} />
        </div>
        <div className="sm:col-span-2">
          <Label htmlFor="tf-notes">Notes</Label>
          <Textarea id="tf-notes" {...register('notes')} />
        </div>
      </form>
    </Modal>
  );
}
