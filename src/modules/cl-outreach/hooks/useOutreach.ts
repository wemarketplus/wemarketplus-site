import { GPS_CHECKINS_FIXTURE, MILEAGE_FIXTURE } from '@/shared/fixtures';

export function useOutreach() {
  return {
    checkIns: GPS_CHECKINS_FIXTURE,
    mileage: MILEAGE_FIXTURE,
    log: GPS_CHECKINS_FIXTURE,
    isUsingFixture: true,
  };
}
