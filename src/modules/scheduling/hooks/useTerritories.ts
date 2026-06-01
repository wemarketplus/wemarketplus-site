import { TERRITORIES_FIXTURE } from '@/shared/fixtures';

export function useTerritories() {
  return { territories: TERRITORIES_FIXTURE, isUsingFixture: true };
}
