import type {
  IntelligenceKpi,
  LeaderboardRow,
  RangeOption,
} from '../types/intelligenceTypes';

export const REVENUE_KPIS: readonly IntelligenceKpi[] = [
  { id: 'attributable', label: 'Attributable revenue', value: '$184k', delta: '+12.4%' },
  { id: 'avg-ltv', label: 'Avg referral LTV', value: '$22.4k', delta: '+3.1%' },
  { id: 'time-to-admit', label: 'Time to admit', value: '4.1 days', delta: '-0.6 days' },
  { id: 'admit-rate', label: 'Admit rate', value: '32%', delta: '+2 pp' },
];

export const LEADERBOARD: readonly LeaderboardRow[] = [
  { id: 'avery', marketer: 'Avery Cole', admissions: 18, conversion: 0.33 },
  { id: 'jordan', marketer: 'Jordan Reese', admissions: 12, conversion: 0.24 },
  { id: 'sam', marketer: 'Sam Brennan', admissions: 9, conversion: 0.28 },
];

export const RANGES: ReadonlyArray<RangeOption> = [
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: 'mtd', label: 'Month to date' },
];
