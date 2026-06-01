import { OWNER_KPIS } from '../constants/ownerFixtures';
import type { OwnerKPI } from '../types/ownerPortalTypes';

// Single source of truth for the dashboard KPI strip. Will eventually wrap
// useGetOwnerKpisQuery; today it just returns the fixture.
export function useOwnerKpis(): { kpis: readonly OwnerKPI[]; isUsingFixture: boolean } {
  return { kpis: OWNER_KPIS, isUsingFixture: true };
}
