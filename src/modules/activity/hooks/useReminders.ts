import { useMemo } from 'react';
import type { Reminder } from '@/shared/types';
import { useEntityCrud } from '@/shared/ui/entity';
import {
  useCreateTaskMutation,
  useDeleteTaskMutation,
  useListTasksQuery,
  useUpdateTaskMutation,
} from '../api/activityApi';
import { TaskStatus } from '../types/activityTypes';
import { toReminder, toCreateTask, toUpdateTask } from '../utils/activityMappers';
import { bucketReminders } from '../utils/activityUtils';
import type { TaskFormValues } from '../schema/taskSchema';
import type { TaskRecord } from '../types/activityTypes';

export function useReminders() {
  const { data } = useListTasksQuery();

  // Raw task records back every reminder; kept so the edit form can seed from
  // the full record (the Reminder view-model drops fields the form needs).
  const records = useMemo<readonly TaskRecord[]>(() => data?.data ?? [], [data]);

  const reminders = useMemo<readonly Reminder[]>(() => {
    return records
      .filter((t) => t.dueDate && t.status !== TaskStatus.Completed && t.status !== TaskStatus.Cancelled)
      .map(toReminder);
  }, [records]);

  const buckets = useMemo(() => bucketReminders(reminders), [reminders]);
  const overdueCount = buckets.overdue.length;

  const [createTask, createState] = useCreateTaskMutation();
  const [updateTask, updateState] = useUpdateTaskMutation();
  const [deleteTask] = useDeleteTaskMutation();

  const crud = useEntityCrud<
    TaskRecord,
    ReturnType<typeof toCreateTask>,
    ReturnType<typeof toUpdateTask>
  >({
    noun: 'reminder',
    create: createTask,
    update: updateTask,
    remove: deleteTask,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (t) => t.title || 'reminder',
  });

  const submit = (values: TaskFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateTask(values))
      : crud.submitCreate(toCreateTask(values));

  // Look up the raw record for a reminder row so edit/delete can act on it.
  const recordById = (id: string) => records.find((t) => t.id === id);

  return { reminders, buckets, overdueCount, records, crud, submit, recordById, isUsingFixture: false };
}
