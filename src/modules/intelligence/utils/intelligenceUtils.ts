import type { LeaderboardRow } from '../types/intelligenceTypes';

export function rankLeaderboard(rows: readonly LeaderboardRow[]): LeaderboardRow[] {
  return [...rows].sort((a, b) => b.admissions - a.admissions);
}

export function formatConversion(conversion: number): string {
  return `${(conversion * 100).toFixed(0)}%`;
}
