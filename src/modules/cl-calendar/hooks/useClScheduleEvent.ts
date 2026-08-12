import { useMemo, useState } from 'react';
import { toast } from 'sonner';
import { useListClLeadsQuery } from '@/modules/cl-leads';
import { useCreateClVisitMutation } from '@/modules/cl-outreach';
import { useListClReferralSourcesQuery } from '@/modules/cl-referrals';
import { useCreateClTourMutation } from '@/modules/cl-tours';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { localInputToIso } from '@/shared/utils/dateFormatter';
import { CL_CALENDAR_FETCH_LIMIT } from '../constants/clCalendarConstants';
import type { ClScheduleFormValues } from '../schema/clCalendarSchema';

export interface ClScheduleController {
  open: boolean;
  /** Opens the modal pre-set to a day (`YYYY-MM-DD`). */
  openFor: (dayKey: string) => void;
  close: () => void;
  /** The day the modal was opened for, seeding the date input. */
  dayKey: string;
  leadOptions: ReadonlyArray<{ value: string; label: string }>;
  referralSourceOptions: ReadonlyArray<{ value: string; label: string }>;
  isSaving: boolean;
  /** Resolves true when the record was created (the modal then closes). */
  submit: (values: ClScheduleFormValues) => Promise<boolean>;
}

/**
 * Creating from the calendar.
 *
 * Writes to the SAME endpoints the Tour Scheduler and Outreach Log write to —
 * POST /cl/tours and POST /cl/outreach-visits — so a tour booked here is the same
 * record, in the same list, with the same validation. The guide's "anything you'd
 * normally track in Outreach Log can be scheduled here first" is only true if
 * these are one record and not a parallel calendar table.
 *
 * The mutations invalidate their own tags, so the grid refreshes without this
 * hook knowing anything about the calendar's queries.
 */
export function useClScheduleEvent(): ClScheduleController {
  const [open, setOpen] = useState(false);
  const [dayKey, setDayKey] = useState('');

  const [createTour, tourState] = useCreateClTourMutation();
  const [createVisit, visitState] = useCreateClVisitMutation();

  // Pickers, loaded only while the modal is open.
  const leads = useListClLeadsQuery(
    { page: 1, limit: CL_CALENDAR_FETCH_LIMIT },
    { skip: !open },
  );
  const sources = useListClReferralSourcesQuery(
    { page: 1, limit: CL_CALENDAR_FETCH_LIMIT },
    { skip: !open },
  );

  const leadOptions = useMemo(
    () =>
      (leads.data?.data ?? []).map((lead) => ({
        value: lead.id,
        label:
          [lead.firstName, lead.lastName].filter(Boolean).join(' ').trim() ||
          'Lead',
      })),
    [leads.data],
  );

  const referralSourceOptions = useMemo(
    () =>
      (sources.data?.data ?? []).map((source) => ({
        value: source.id,
        label: source.organization
          ? `${source.name} — ${source.organization}`
          : source.name,
      })),
    [sources.data],
  );

  const submit = async (values: ClScheduleFormValues): Promise<boolean> => {
    try {
      if (values.kind === 'tour') {
        // datetime-local is a zoneless wall clock; convert in the user's zone so
        // a 2pm tour is stored as 2pm here, not 2pm UTC.
        const iso = localInputToIso(values.when);
        if (!iso) {
          toast.error('Pick a valid date and time');
          return false;
        }
        await createTour({
          scheduledAt: iso,
          ...(values.leadId ? { leadId: values.leadId } : {}),
          ...(values.guideUserId ? { guideUserId: values.guideUserId } : {}),
          ...(values.durationMin
            ? { durationMin: Number(values.durationMin) }
            : {}),
          ...(values.notes?.trim() ? { notes: values.notes.trim() } : {}),
        }).unwrap();
        toast.success('Tour scheduled');
        return true;
      }

      // 'visit' and 'lunch' are one record; only the type differs. visitDate is a
      // DATE column, so the raw YYYY-MM-DD goes straight through with no zone
      // conversion — converting it would be the bug.
      await createVisit({
        visitDate: values.when,
        visitType: values.kind === 'lunch' ? 'lunch_and_learn' : 'in_person',
        ...(values.locationName?.trim()
          ? { locationName: values.locationName.trim() }
          : {}),
        ...(values.contactName?.trim()
          ? { contactName: values.contactName.trim() }
          : {}),
        ...(values.referralSourceId
          ? { referralSourceId: values.referralSourceId }
          : {}),
        ...(values.notes?.trim() ? { notes: values.notes.trim() } : {}),
      }).unwrap();
      toast.success(
        values.kind === 'lunch' ? 'Physician lunch scheduled' : 'Visit scheduled',
      );
      return true;
    } catch (error) {
      toast.error(extractApiErrorMessage(error, 'Could not schedule that'));
      return false;
    }
  };

  return {
    open,
    openFor: (key: string) => {
      setDayKey(key);
      setOpen(true);
    },
    close: () => setOpen(false),
    dayKey,
    leadOptions,
    referralSourceOptions,
    isSaving: tourState.isLoading || visitState.isLoading,
    submit,
  };
}
