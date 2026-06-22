import { ACTIVITY_DAILY_GOALS } from '../constants/activityConstants';
import { useListGoalsQuery } from '../api/activityApi';
import { toDailyGoal } from '../utils/activityMappers';

export function useDailyGoals() {
  const { data } = useListGoalsQuery();
  if (data && data.data.length > 0) {
    return { goals: data.data.map(toDailyGoal), isUsingFixture: false };
  }
  return { goals: ACTIVITY_DAILY_GOALS, isUsingFixture: true };
}
