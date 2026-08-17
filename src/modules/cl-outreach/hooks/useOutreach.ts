import { useMemo } from 'react';
import { useListClVisitsQuery } from '../api/clOutreachApi';
import { toCheckIn } from '../utils/clOutreachMappers';

// The GPS check-in lens over /cl/outreach-visits. It used to also derive a
// `mileage` list from the same rows; mileage now lives on the shared
// `mileage_logs` screen (modules/field), so this returns the one projection.
export function useOutreach() {
  const { data } = useListClVisitsQuery();

  const checkIns = useMemo(
    () => (data ? data.data.map(toCheckIn) : []),
    [data],
  );

  return { checkIns };
}
