import type { IntelligenceKpi, LeaderboardRow } from '../types/intelligenceTypes';

export function useIntelligence() {
  // No backend endpoint exists for revenue intelligence yet, so there is no
  // tenant data to render. Return empty collections and flag the empty state.
  const kpis: IntelligenceKpi[] = [];
  const leaderboard: LeaderboardRow[] = [];

  return {
    kpis,
    leaderboard,
    isEmpty: true,
  };
}
