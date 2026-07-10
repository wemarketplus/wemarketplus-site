import { useMemo } from 'react';
import { useListClToursQuery } from '../api/clToursApi';
import { mapClTour, sortByDate } from '../utils/clToursUtils';

export function useTours() {
  const { data } = useListClToursQuery();
  const tours = useMemo(
    () => sortByDate(data && data.data.length > 0 ? data.data.map(mapClTour) : []),
    [data],
  );
  return { tours, isUsingFixture: false };
}
