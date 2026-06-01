import { ACTIVITY_DAILY_GOALS } from '../constants/activityConstants';

export function useDailyGoals() {
  return { goals: ACTIVITY_DAILY_GOALS, isUsingFixture: true };
}
