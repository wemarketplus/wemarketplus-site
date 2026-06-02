import type { Territory } from '@/shared/types';

// Returns total admissions across all visible territories. Handy for footer
// summaries on the page.
export function totalAdmissions(territories: readonly Territory[]): number {
  return territories.reduce((n, t) => n + t.admissionsCount, 0);
}

// Highest admissions count across territories, floored at 1 so it is safe to
// use as a divisor when normalizing heat-map intensity.
export function maxAdmissions(territories: readonly Territory[]): number {
  return Math.max(...territories.map((t) => t.admissionsCount), 1);
}
