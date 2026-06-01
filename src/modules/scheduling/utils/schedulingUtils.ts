import type { Territory } from '@/shared/types';

// Returns total admissions across all visible territories. Handy for footer
// summaries on the page.
export function totalAdmissions(territories: readonly Territory[]): number {
  return territories.reduce((n, t) => n + t.admissionsCount, 0);
}
