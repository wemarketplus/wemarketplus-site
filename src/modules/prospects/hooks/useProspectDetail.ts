import { useCallback, useState } from 'react';
import { toast } from 'sonner';
import { useAppDispatch } from '@/app/hooks';
import { useCreateNoteMutation, useListNotesQuery } from '@/modules/activity';
import { useScheduleVisitMutation } from '@/modules/appointments';
import { useGetReferralQuery } from '@/modules/referrals';
import type { CreateNoteRequest } from '@/modules/activity/types/activityTypes';
import type { ScheduleVisitRequest } from '@/modules/appointments/types/appointmentsTypes';
import { prospectsApi, useGetProspectQuery } from '../api/prospectsApi';
import { PROSPECTS_TAGS } from '../constants/prospectsConstants';

const HISTORY_LIMIT = 50;

/**
 * Drives the prospect detail drawer: the pipeline row, the account it came from,
 * and its team notes.
 *
 * The linked ACCOUNT is fetched separately and only when the prospect has one.
 * Showing the facility by name is the visible proof that the fan-out worked — a
 * prospect created from free text now points at a real account record rather
 * than holding a string, and the drawer would look identical either way if it
 * just echoed `facilityName`.
 */
export function useProspectDetail() {
  const dispatch = useAppDispatch();
  const [openId, setOpenId] = useState<string | null>(null);
  const [isLogging, setIsLogging] = useState(false);
  const [isScheduling, setIsScheduling] = useState(false);

  // `currentData`, NOT `data`. RTK Query documents `data` as "the latest
  // returned result REGARDLESS of hook arg" — so it keeps the previous
  // prospect after the query is skipped or the id changes. Reading `data` here
  // both kept the drawer open after Close (see `isOpen` below) and flashed the
  // previously-viewed prospect when opening a different row.
  const { currentData: prospect, isFetching } = useGetProspectQuery(
    openId ?? '',
    { skip: openId === null },
  );
  const { currentData: notes, isFetching: isNotesFetching } = useListNotesQuery(
    openId ? { prospectId: openId, limit: HISTORY_LIMIT } : undefined,
    { skip: openId === null },
  );
  const { currentData: account } = useGetReferralQuery(
    prospect?.referralSourceId ?? '',
    { skip: !prospect?.referralSourceId },
  );

  const [createNote] = useCreateNoteMutation();
  const [scheduleVisit] = useScheduleVisitMutation();

  const close = useCallback(() => {
    setOpenId(null);
    setIsLogging(false);
    setIsScheduling(false);
  }, []);

  const addNote = useCallback(
    async (body: CreateNoteRequest): Promise<boolean> => {
      try {
        await createNote(body).unwrap();
        // Cross-slice: a note can change what the prospect row shows (and the
        // backend re-scores triage on write), so the prospect must be refetched
        // rather than trusting activityApi's own tag, which cannot reach it.
        dispatch(
          prospectsApi.util.invalidateTags([
            { type: PROSPECTS_TAGS.Detail, id: body.prospectId },
          ]),
        );
        toast.success('Note added');
        return true;
      } catch {
        toast.error('Could not add the note. Please try again.');
        return false;
      }
    },
    [createNote, dispatch],
  );

  const schedule = useCallback(
    async (body: ScheduleVisitRequest): Promise<boolean> => {
      try {
        await scheduleVisit(body).unwrap();
        toast.success('Visit scheduled');
        return true;
      } catch {
        toast.error('Could not schedule the visit. Please try again.');
        return false;
      }
    },
    [scheduleVisit],
  );

  return {
    openId,
    // The drawer's visibility is driven by THIS, not by whether data is
    // present. Deriving it from the query result meant Close set `openId` to
    // null while the retained `data` held the modal open — neither the × nor
    // the Close button appeared to do anything.
    isOpen: openId !== null,
    prospect,
    account,
    notes: notes?.data ?? [],
    isLoading: isFetching,
    isNotesLoading: isNotesFetching,
    open: (id: string) => setOpenId(id),
    close,
    isLogging,
    startLogging: () => setIsLogging(true),
    stopLogging: () => setIsLogging(false),
    addNote,
    isScheduling,
    startScheduling: () => setIsScheduling(true),
    stopScheduling: () => setIsScheduling(false),
    schedule,
  };
}
