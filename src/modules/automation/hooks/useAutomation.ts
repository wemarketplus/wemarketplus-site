import { useCallback, useMemo, useState } from 'react';
import { toast } from 'sonner';
import { useAppDispatch } from '@/app/hooks';
import { confirm } from '@/shared/ui/feedback';
import { dailyQueueApi } from '@/modules/daily-queue';
import { useListProspectsQuery } from '@/modules/prospects';
import type { EntitySelectOption } from '@/shared/ui/entity';
import {
  useCancelFollowUpMutation,
  useCreateFollowUpMutation,
  useListFollowUpsQuery,
} from '../api/automationApi';
import type { FollowUpFormValues } from '../schema/followUpSchema';
import type { FollowUpAutomationRecord } from '../types/automationTypes';

/**
 * The backend paginator caps `limit` at 100 (MAX_LIMIT), so this is the widest
 * single page the picker can ask for. A tenant past that needs a type-ahead
 * picker backed by a server search, which is a change to the prospects module
 * rather than something to fake here by fetching pages in a loop.
 */
const PROSPECT_PICKER_LIMIT = 100;

/** Stable identity so the memos below do not rerun on every render. */
const NO_PROSPECTS = [] as const;

/**
 * Everything the Automation page does.
 *
 * The prospect list is fetched ONCE and used twice — as the picker's options and
 * as the id -> name lookup for the table. That is why the backend response
 * carries no patient name: the client is already holding the list, so resolving
 * a label server-side would be one extra query per row for a string that is
 * free here.
 */
export function useAutomation() {
  const dispatch = useAppDispatch();
  const { data, isLoading, isError, isFetching, refetch } =
    useListFollowUpsQuery();
  const { data: prospectPage, isLoading: prospectsLoading } =
    useListProspectsQuery({ limit: PROSPECT_PICKER_LIMIT });

  const [createFollowUp, createState] = useCreateFollowUpMutation();
  const [cancelFollowUp] = useCancelFollowUpMutation();
  const [formOpen, setFormOpen] = useState(false);
  const [cancellingId, setCancellingId] = useState<string | null>(null);

  const prospects = prospectPage?.data ?? NO_PROSPECTS;

  const prospectOptions = useMemo<readonly EntitySelectOption[]>(
    () =>
      prospects.map((prospect) => ({
        value: prospect.id,
        label: prospect.patientName,
      })),
    [prospects],
  );

  const prospectNameById = useMemo(
    () => new Map(prospects.map((prospect) => [prospect.id, prospect.patientName])),
    [prospects],
  );

  /**
   * Invalidating the DAILY QUEUE after every write is the point of the feature,
   * not housekeeping. The two live in different createApi slices, so
   * `automationApi`'s own tag cannot reach the queue — a marketer who schedules
   * something for today and then opens Daily tasks would be shown a cached list
   * that does not contain it, and would reasonably conclude the automation had
   * not been created.
   */
  const refreshDailyQueue = useCallback(() => {
    dispatch(dailyQueueApi.util.invalidateTags(['DailyQueue']));
  }, [dispatch]);

  const submit = useCallback(
    async (values: FollowUpFormValues): Promise<boolean> => {
      try {
        await createFollowUp({
          prospectId: values.prospectId,
          title: values.title.trim(),
          dueDate: values.dueDate,
          // Blank must be sent as absent, not as "": the backend length check
          // would accept the empty string and store it, leaving a cadence note
          // that renders as a stray blank line forever.
          cadenceNote: values.cadenceNote?.trim() || undefined,
        }).unwrap();
        refreshDailyQueue();
        toast.success('Follow-up scheduled');
        setFormOpen(false);
        return true;
      } catch {
        toast.error('Could not schedule the follow-up. Please try again.');
        return false;
      }
    },
    [createFollowUp, refreshDailyQueue],
  );

  const cancel = useCallback(
    async (row: FollowUpAutomationRecord) => {
      const confirmed = await confirm({
        title: 'Cancel this follow-up?',
        body: `"${row.title}" will stop appearing in your Daily tasks. The record is kept, not deleted.`,
        confirmLabel: 'Cancel follow-up',
        cancelLabel: 'Keep it',
      });
      if (!confirmed) return;

      setCancellingId(row.id);
      try {
        await cancelFollowUp(row.id).unwrap();
        refreshDailyQueue();
        toast.success('Follow-up cancelled');
      } catch {
        toast.error('Could not cancel the follow-up. Please try again.');
      } finally {
        setCancellingId(null);
      }
    },
    [cancelFollowUp, refreshDailyQueue],
  );

  return {
    followUps: data ?? [],
    isLoading,
    isError,
    isFetching,
    refetch,
    prospectOptions,
    prospectsLoading,
    prospectNameById,
    formOpen,
    openForm: () => setFormOpen(true),
    closeForm: () => setFormOpen(false),
    submit,
    isSaving: createState.isLoading,
    cancel,
    cancellingId,
  };
}
