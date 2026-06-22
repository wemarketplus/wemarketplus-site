import { useMemo } from 'react';
import { GPS_CHECKINS_FIXTURE, MILEAGE_FIXTURE } from '@/shared/fixtures';
import { useListClVisitsQuery } from '../api/clOutreachApi';
import { toCheckIn, toMileage } from '../utils/clOutreachMappers';

export function useOutreach() {
  const { data } = useListClVisitsQuery();
  const live = Boolean(data && data.data.length > 0);

  const checkIns = useMemo(
    () => (live ? data!.data.map(toCheckIn) : GPS_CHECKINS_FIXTURE),
    [data, live],
  );
  const mileage = useMemo(
    () => (live ? data!.data.filter((v) => v.miles != null).map(toMileage) : MILEAGE_FIXTURE),
    [data, live],
  );

  return { checkIns, mileage, log: checkIns, isUsingFixture: !live };
}
