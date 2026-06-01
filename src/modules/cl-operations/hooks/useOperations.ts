import {
  APARTMENTS_FIXTURE,
  HOUSEKEEPING_FIXTURE,
  MAINTENANCE_FIXTURE,
  MAKE_READY_FIXTURE,
} from '@/shared/fixtures';

export function useOperations() {
  return {
    apartments: APARTMENTS_FIXTURE,
    makeReady: MAKE_READY_FIXTURE,
    maintenance: MAINTENANCE_FIXTURE,
    housekeeping: HOUSEKEEPING_FIXTURE,
    isUsingFixture: true,
  };
}
