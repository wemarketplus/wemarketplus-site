import { useCallback, useState } from 'react';
import { toast } from 'sonner';
import { useAppDispatch } from '@/app/hooks';
import { jobsApi } from '@/modules/jobs/api/jobsApi';
import {
  useCompleteAppointmentMutation,
  useCreateAppointmentMutation,
} from '../api/appointmentsApi';
import type { NewAppointmentFormValues } from '../schema/appointmentSchema';
import type { AppointmentType } from '../types/appointmentsTypes';
import type {
  AppointmentRecord,
  CompleteAppointmentRequest,
} from '../types/appointmentsTypes';

/**
 * Completing a visit. The backend may chain a follow-up job, so on success the jobs
 * cache is invalidated and the chained job is surfaced in the toast rather than
 * appearing silently on the Jobs screen.
 */
export function useAppointmentActions() {
  const dispatch = useAppDispatch();
  const [pending, setPending] = useState<AppointmentRecord | null>(null);
  const [scheduleOpen, setScheduleOpen] = useState(false);
  const [complete, { isLoading: isCompleting }] =
    useCompleteAppointmentMutation();
  const [create, { isLoading: isScheduling }] = useCreateAppointmentMutation();

  const submitSchedule = useCallback(
    async (values: NewAppointmentFormValues) => {
      try {
        await create({
          jobId: values.jobId,
          title: values.title,
          // datetime-local yields a local wall-clock string with no zone; new Date()
          // interprets it as local, and toISOString sends the correct instant.
          startAt: new Date(values.startAt).toISOString(),
          endAt: new Date(values.endAt).toISOString(),
          appointmentType: values.appointmentType as AppointmentType,
          // Blank means "leave it to the server", which assigns the caller. An
          // empty string would fail @IsUUID, so it is dropped rather than sent.
          assignedRep: values.assignedRep || undefined,
          location: values.location?.trim() || undefined,
          // Sent as a pair or not at all — the server 400s a lone half. The
          // form only ever sets both (the picker writes them together) or
          // neither (a virtual/call appointment, whose location is a link).
          locationLat: values.locationLat,
          locationLng: values.locationLng,
        }).unwrap();
        toast.success('Appointment scheduled.');
        setScheduleOpen(false);
        return true;
      } catch {
        toast.error('Could not schedule that appointment.');
        return false;
      }
    },
    [create],
  );

  const submitComplete = useCallback(
    async (id: string, body: CompleteAppointmentRequest) => {
      try {
        const result = await complete({ id, body }).unwrap();
        if (result.nextJobId) {
          dispatch(
            jobsApi.util.invalidateTags([
              { type: 'Jobs.List', id: 'PARTIAL-LIST' },
            ]),
          );
          toast.success('Visit logged · follow-up job created.');
        } else {
          toast.success('Visit logged.');
        }
        setPending(null);
        return true;
      } catch {
        toast.error('Could not log that visit.');
        return false;
      }
    },
    [complete, dispatch],
  );

  return {
    pending,
    openComplete: setPending,
    closeComplete: () => setPending(null),
    isCompleting,
    submitComplete,
    scheduleOpen,
    openSchedule: () => setScheduleOpen(true),
    closeSchedule: () => setScheduleOpen(false),
    isScheduling,
    submitSchedule,
  };
}
