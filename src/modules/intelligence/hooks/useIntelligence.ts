import { LEADERBOARD, REVENUE_KPIS } from '../constants/intelligenceConstants';
import { rankLeaderboard } from '../utils/intelligenceUtils';

export function useIntelligence() {
  return {
    kpis: REVENUE_KPIS,
    leaderboard: rankLeaderboard(LEADERBOARD),
    isUsingFixture: true,
  };
}
