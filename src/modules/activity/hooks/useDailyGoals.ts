import { useListGoalsQuery } from '../api/activityApi';
import { toDailyGoal } from '../utils/activityMappers';

export function useDailyGoals() {
  const { data } = useListGoalsQuery();
  const goals = data?.data ? data.data.map(toDailyGoal) : [];
  return { goals, isUsingFixture: false };
}
