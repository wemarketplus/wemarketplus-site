import type { LeaderboardRow } from '../types/intelligenceTypes';

export function rankLeaderboard(rows: readonly LeaderboardRow[]): LeaderboardRow[] {
  return [...rows].sort((a, b) => b.admissions - a.admissions);
}
