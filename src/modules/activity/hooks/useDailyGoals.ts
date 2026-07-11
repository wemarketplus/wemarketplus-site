import { useMemo } from 'react';
import { useEntityCrud } from '@/shared/ui/entity';
import {
  useCreateGoalMutation,
  useDeleteGoalMutation,
  useListGoalsQuery,
  useUpdateGoalMutation,
} from '../api/activityApi';
import { toDailyGoal, toCreateGoal, toUpdateGoal } from '../utils/activityMappers';
import type { GoalFormValues } from '../schema/goalSchema';
import type { GoalRecord } from '../types/activityTypes';

export function useDailyGoals() {
  const { data } = useListGoalsQuery();

  const records = useMemo<readonly GoalRecord[]>(() => data?.data ?? [], [data]);
  const goals = useMemo(() => records.map(toDailyGoal), [records]);

  const [createGoal, createState] = useCreateGoalMutation();
  const [updateGoal, updateState] = useUpdateGoalMutation();
  const [deleteGoal] = useDeleteGoalMutation();

  const crud = useEntityCrud<
    GoalRecord,
    ReturnType<typeof toCreateGoal>,
    ReturnType<typeof toUpdateGoal>
  >({
    noun: 'goal',
    create: createGoal,
    update: updateGoal,
    remove: deleteGoal,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (g) => g.title || 'goal',
  });

  const submit = (values: GoalFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateGoal(values))
      : crud.submitCreate(toCreateGoal(values));

  const recordById = (id: string) => records.find((g) => g.id === id);

  return { goals, records, crud, submit, recordById, isUsingFixture: false };
}
