import { useMemo } from 'react';
import { useListClVisitsQuery } from '../api/clOutreachApi';
import { toCheckIn, toMileage } from '../utils/clOutreachMappers';

export function useOutreach() {
  const { data } = useListClVisitsQuery();

  const checkIns = useMemo(
    () => (data ? data.data.map(toCheckIn) : []),
    [data],
  );
  const mileage = useMemo(
    () => (data ? data.data.filter((v) => v.miles != null).map(toMileage) : []),
    [data],
  );

  return { checkIns, mileage };
}
