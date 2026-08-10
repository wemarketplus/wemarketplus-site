import { useCallback, useState } from 'react';
import { toast } from 'sonner';
import {
  useCreateNoteMutation,
  useListNotesQuery,
} from '@/modules/activity';
import { useScheduleVisitMutation } from '@/modules/appointments';
import type { CreateNoteRequest } from '@/modules/activity/types/activityTypes';
import type { ScheduleVisitRequest } from '@/modules/appointments/types/appointmentsTypes';
import { useAppDispatch } from '@/app/hooks';
import { referralsApi, useGetReferralQuery } from '../api/referralsApi';
import { REFERRALS_TAGS } from '../constants/referralsConstants';

/** Interaction history is a worklist, not an archive; newest N is enough. */
const HISTORY_LIMIT = 50;

/**
 * Drives the referral-source detail drawer: the account, its interaction
 * history, and the two actions taken from it.
 *
 * Both mutations deliberately re-fetch more than they wrote. Logging an
 * interaction changes the account's `lastInteractionAt` and therefore its Cold
 * badge, so invalidating only the note list would leave a just-visited hospital
 * still showing "Cold" until a reload — the exact inconsistency the server-side
 * rule was built to avoid.
 */
export function useReferralSourceDetail() {
  const dispatch = useAppDispatch();
  const [openId, setOpenId] = useState<string | null>(null);
  const [isLogging, setIsLogging] = useState(false);
  const [isScheduling, setIsScheduling] = useState(false);

  // `currentData`, NOT `data` — see useProspectDetail for the full reasoning.
  // `data` survives a skip, which kept this drawer open after Close.
  const { currentData: source, isFetching } = useGetReferralQuery(
    openId ?? '',
    { skip: openId === null },
  );
  const { currentData: notes, isFetching: isNotesFetching } = useListNotesQuery(
    openId ? { referralSourceId: openId, limit: HISTORY_LIMIT } : undefined,
    { skip: openId === null },
  );

  const [createNote] = useCreateNoteMutation();
  const [scheduleVisit] = useScheduleVisitMutation();

  const open = useCallback((id: string) => setOpenId(id), []);
  const close = useCallback(() => {
    setOpenId(null);
    setIsLogging(false);
    setIsScheduling(false);
  }, []);

  const logInteraction = useCallback(
    async (body: CreateNoteRequest): Promise<boolean> => {
      try {
        await createNote(body).unwrap();
        // `activityApi` and `referralsApi` are separate createApi slices, so the
        // note mutation's own `invalidatesTags: ['Note']` cannot reach the
        // account. Without this explicit cross-slice invalidation a
        // just-visited hospital keeps its Cold badge and stale "Never
        // contacted" until a full reload — the server would be right and the
        // screen would be wrong.
        dispatch(
          referralsApi.util.invalidateTags([
            { type: REFERRALS_TAGS.Detail, id: body.referralSourceId },
            { type: REFERRALS_TAGS.List, id: 'PARTIAL-LIST' },
          ]),
        );
        toast.success('Interaction logged');
        return true;
      } catch {
        toast.error('Could not log the interaction. Please try again.');
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
    /** Visibility is driven by explicit state, never by data presence. */
    isOpen: openId !== null,
    source,
    notes: notes?.data ?? [],
    isLoading: isFetching,
    isNotesLoading: isNotesFetching,
    open,
    close,
    isLogging,
    startLogging: () => setIsLogging(true),
    stopLogging: () => setIsLogging(false),
    logInteraction,
    isScheduling,
    startScheduling: () => setIsScheduling(true),
    stopScheduling: () => setIsScheduling(false),
    schedule,
  };
}
