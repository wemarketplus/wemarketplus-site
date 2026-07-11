import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { Button, Input, Label, Select, Textarea } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import type { EntitySelectOption } from '@/shared/ui/entity';
import { CL_TOUR_STATUS } from '../constants/clToursApiConstants';
import { TOUR_DURATION_OPTIONS, TOUR_STATUS_OPTIONS } from '../constants/clToursConstants';
import { tourSchema, type TourFormValues } from '../schema/clTourSchema';
import { toTourFormValues } from '../utils/clToursUtils';
import type { ClTourRecord } from '../types/clToursApiTypes';

const EMPTY: TourFormValues = {
  leadId: '',
  scheduledAt: '',
  status: CL_TOUR_STATUS.Scheduled,
  durationMin: '60',
  outcome: '',
  notes: '',
};

interface TourFormModalProps {
  open: boolean;
  isSaving: boolean;
  editing?: ClTourRecord | null;
  leadOptions: readonly EntitySelectOption[];
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
  onClose,
  onSubmit,
}: TourFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<TourFormValues>({
    resolver: zodResolver(tourSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toTourFormValues(editing) : EMPTY);
  }, [open, editing, reset]);

  const close = () => {
    reset(EMPTY);
    onClose();
  };

  const submit = handleSubmit(async (values) => {
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
          <Button variant="ghost" onClick={close} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={isSaving}>
            {isSaving ? 'Saving…' : editing ? 'Save changes' : 'Book tour'}
          </Button>
        </>
      }
    >
      <form onSubmit={submit} className="grid grid-cols-1 gap-4 sm:grid-cols-2">
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
        <div className="sm:col-span-2">
          <Label htmlFor="tf-when">Date &amp; time</Label>
          <Input id="tf-when" type="datetime-local" {...register('scheduledAt')} />
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
