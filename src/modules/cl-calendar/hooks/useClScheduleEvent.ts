import { useMemo, useState } from 'react';
import { toast } from 'sonner';
import { useListClLeadsQuery } from '@/modules/cl-leads';
import { useScheduleClVisitMutation, VISIT_TYPE } from '@/modules/cl-outreach';
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
 * Writes the SAME RECORDS the Tour Scheduler and Outreach Log write — cl_tours
 * and cl_outreach_visits — so a tour booked here appears in the same list, and
 * the guide's "anything you'd normally track in Outreach Log can be scheduled
 * here first" stays true rather than implying a parallel calendar table.
 *
 * The visit half posts to /cl/outreach-visits/SCHEDULE rather than the plain
 * create route. Same row, same service, one difference: the scheduling route
 * floors the date server-side, because booking into a day that has already gone
 * is always a mistake. The log's own route deliberately has no floor, since
 * writing up a visit that already happened is its whole purpose — the two rules
 * cannot live on one endpoint, and while they did, the calendar's floor silently
 * blocked back-dated logging.
 *
 * The mutations invalidate their own tags, so the grid refreshes without this
 * hook knowing anything about the calendar's queries.
 */
export function useClScheduleEvent(): ClScheduleController {
  const [open, setOpen] = useState(false);
  const [dayKey, setDayKey] = useState('');

  const [createTour, tourState] = useCreateClTourMutation();
  const [scheduleVisit, visitState] = useScheduleClVisitMutation();

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
          // The route, only when it was actually set. Coordinates go in PAIRS —
          // the picker writes both or neither, and the server 400s a lone half.
          ...(values.fromLocation?.trim()
            ? { fromLocation: values.fromLocation.trim() }
            : {}),
          ...(values.fromLat !== undefined && values.fromLng !== undefined
            ? { fromLat: values.fromLat, fromLng: values.fromLng }
            : {}),
          ...(values.toLocation?.trim()
            ? { toLocation: values.toLocation.trim() }
            : {}),
          ...(values.toLat !== undefined && values.toLng !== undefined
            ? { toLat: values.toLat, toLng: values.toLng }
            : {}),
        }).unwrap();
        toast.success('Tour scheduled');
        return true;
      }

      // 'visit' and 'lunch' are one record; only the type differs. visitDate is a
      // DATE column, so the raw YYYY-MM-DD goes straight through with no zone
      // conversion — converting it would be the bug.
      await scheduleVisit({
        visitDate: values.when,
        /**
         * The CANONICAL visit-type values from VISIT_TYPE_OPTIONS — not
         * hand-written strings.
         *
         * Both of the old literals were wrong, in the two different ways a
         * free-form varchar lets you be wrong:
         *
         *  - `'lunch_and_learn'` matched NOTHING. The canonical value is
         *    `lunch_learn` (no "and"), so `visitTypeLabel` fell through to its
         *    raw-string fallback and the Outreach Log printed the slug itself,
         *    while the log's Type filter — an exact `WHERE visitType = …` —
         *    could never select the row.
         *  - `'in_person'` matched, but it is the WRONG type: the user picked
         *    "Facility visit" and got the generic in-person bucket, so the log
         *    reported a type nobody chose and filtering by facility visits
         *    missed every one the calendar created.
         *
         * Imported rather than retyped so the two screens cannot drift again.
         */
        visitType: values.kind === 'lunch' ? VISIT_TYPE.LunchLearn : VISIT_TYPE.FacilityVisit,
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
