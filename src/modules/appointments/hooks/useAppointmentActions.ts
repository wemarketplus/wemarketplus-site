import { useCallback, useState } from 'react';
import { toast } from 'sonner';
import { useAppDispatch } from '@/app/hooks';
import { jobsApi } from '@/modules/jobs/api/jobsApi';
import { useCompleteAppointmentMutation } from '../api/appointmentsApi';
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
  const [complete, { isLoading: isCompleting }] =
    useCompleteAppointmentMutation();

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
  };
}
