import { useCallback, useState } from 'react';
import { toast } from 'sonner';
import { useAppDispatch } from '@/app/hooks';
import { useUpdateTaskMutation } from '@/modules/activity';
import { TaskStatus } from '@/modules/activity/types/activityTypes';
import { dailyQueueApi, useGetDailyQueueQuery } from '../api/dailyQueueApi';

/**
 * The marketer's day, plus the one action taken directly from it.
 *
 * Completing a task has to invalidate the QUEUE, not just the task list: the two
 * live in different createApi slices, so `activityApi`'s own tag cannot reach
 * this one and the completed row would sit there looking undone.
 */
export function useDailyQueue() {
  const dispatch = useAppDispatch();
  const { data, isLoading, isError, isFetching, refetch } =
    useGetDailyQueueQuery();
  const [updateTask] = useUpdateTaskMutation();
  const [completingId, setCompletingId] = useState<string | null>(null);

  const completeTask = useCallback(
    async (id: string) => {
      setCompletingId(id);
      try {
        await updateTask({
          id,
          patch: { status: TaskStatus.Completed },
        }).unwrap();
        dispatch(dailyQueueApi.util.invalidateTags(['DailyQueue']));
        toast.success('Task completed');
      } catch {
        toast.error('Could not complete the task. Please try again.');
      } finally {
        setCompletingId(null);
      }
    },
    [dispatch, updateTask],
  );

  return {
    queue: data,
    isLoading,
    isError,
    isFetching,
    refetch,
    completeTask,
    completingId,
  };
}
