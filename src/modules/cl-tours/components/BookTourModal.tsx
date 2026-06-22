import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { Button, Input, Label, Select, Textarea } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import { CL_TOUR_STATUS, CL_TOUR_STATUS_OPTIONS } from '../constants/clToursApiConstants';
import { newTourSchema, type NewTourFormValues } from '../schema/clTourSchema';
import type { BookTourModalProps } from '../types/clToursApiTypes';

// Book Tour modal — presentational. The page owns useBookTour.
export function BookTourModal({ open, isSaving, onClose, onSubmit: submit }: BookTourModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<NewTourFormValues>({
    resolver: zodResolver(newTourSchema),
    defaultValues: {
      scheduledAt: '',
      status: CL_TOUR_STATUS.Scheduled,
      durationMin: '30',
      notes: '',
    },
  });

  const close = () => {
    reset();
    onClose();
  };

  const onSubmit = async (values: NewTourFormValues) => {
    const ok = await submit(values);
    if (ok) reset();
  };

  return (
    <Modal
      open={open}
      onClose={close}
      title="Book Tour"
      size="md"
      footer={
        <>
          <Button variant="ghost" onClick={close} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={handleSubmit(onSubmit)} disabled={isSaving}>
            {isSaving ? 'Saving…' : 'Book Tour'}
          </Button>
        </>
      }
    >
      <form onSubmit={handleSubmit(onSubmit)} className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <Label htmlFor="bt-when">Date &amp; time</Label>
          <Input id="bt-when" type="datetime-local" {...register('scheduledAt')} />
          {errors.scheduledAt && (
            <p className="mt-1 text-[12px] text-destructive">{errors.scheduledAt.message}</p>
          )}
        </div>
        <div>
          <Label htmlFor="bt-status">Status</Label>
          <Select id="bt-status" {...register('status')}>
            {CL_TOUR_STATUS_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="bt-duration">Duration (min)</Label>
          <Input id="bt-duration" type="number" min={0} {...register('durationMin')} />
        </div>
        <div className="sm:col-span-2">
          <Label htmlFor="bt-notes">Notes</Label>
          <Textarea id="bt-notes" {...register('notes')} />
        </div>
      </form>
    </Modal>
  );
}
