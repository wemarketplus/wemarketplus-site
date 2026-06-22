import { useMemo } from 'react';
import { TOURS_FIXTURE } from '@/shared/fixtures';
import { useListClToursQuery } from '../api/clToursApi';
import { mapClTour, sortByDate } from '../utils/clToursUtils';

export function useTours() {
  const { data } = useListClToursQuery();
  const tours = useMemo(
    () => sortByDate(data && data.data.length > 0 ? data.data.map(mapClTour) : TOURS_FIXTURE),
    [data],
  );
  return { tours, isUsingFixture: !data || data.data.length === 0 };
}
