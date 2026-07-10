import { useState } from 'react';
import { toast } from 'sonner';
import { useCreateClTourMutation } from '../api/clToursApi';
import type { NewTourFormValues } from '../schema/clTourSchema';
import type { CreateClTourRequest } from '../types/clToursApiTypes';

// datetime-local gives "2026-06-25T14:30" (no zone). The backend wants a full
// ISO timestamp, so we let the Date constructor interpret it as local time and
// serialise to ISO. Returns null if the value can't be parsed.
function toIso(local: string): string | null {
  const ms = Date.parse(local);
  return Number.isNaN(ms) ? null : new Date(ms).toISOString();
}

// Orchestrates the Book-tour modal: open/close state plus POST /cl/tours.
export function useBookTour() {
  const [open, setOpen] = useState(false);
  const [createTour, { isLoading }] = useCreateClTourMutation();

  const submit = async (values: NewTourFormValues): Promise<boolean> => {
    const scheduledAt = toIso(values.scheduledAt);
    if (!scheduledAt) {
      toast.error('Could not read the tour date. Please re-pick it.');
      return false;
    }

    const durationMin = values.durationMin?.trim() ? Number(values.durationMin) : undefined;
    const body: CreateClTourRequest = {
      scheduledAt,
      status: values.status,
      ...(durationMin != null && !Number.isNaN(durationMin) ? { durationMin } : {}),
      ...(values.notes?.trim() ? { notes: values.notes.trim() } : {}),
    };

    try {
      await createTour(body).unwrap();
      toast.success('Tour booked');
      setOpen(false);
      return true;
    } catch {
      toast.error('Could not book tour. Please try again.');
      return false;
    }
  };

  return {
    open,
    isSaving: isLoading,
    openModal: () => setOpen(true),
    close: () => setOpen(false),
    submit,
  };
}
