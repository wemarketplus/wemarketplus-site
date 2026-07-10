import type { Territory } from '@/shared/types';

// The territory-performance view (marketer coverage, visits, admissions,
// conversion) is a Gold-tier analytics surface that needs a backend
// aggregation endpoint which does not exist yet. Rather than render fabricated
// numbers, return an empty set and let the page show a "coming soon" state.
// The plain territory CRUD list lives at /territories (real TerritoriesPage).
export function useTerritories(): {
  territories: readonly Territory[];
  isEmpty: boolean;
} {
  return { territories: [], isEmpty: true };
}
