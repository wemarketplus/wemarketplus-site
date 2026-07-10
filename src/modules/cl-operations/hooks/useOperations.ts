import { useMemo } from 'react';
import {
  useListClApartmentsQuery,
  useListClHousekeepingQuery,
  useListClMaintenanceQuery,
  useListClMakeReadyQuery,
} from '../api/clOperationsApi';
import {
  toApartment,
  toHousekeepingTicket,
  toMaintenanceTicket,
  toMakeReady,
} from '../utils/clOperationsMappers';

export function useOperations() {
  const apts = useListClApartmentsQuery();
  const mr = useListClMakeReadyQuery();
  const maint = useListClMaintenanceQuery();
  const hk = useListClHousekeepingQuery();

  const apartments = useMemo(
    () => (apts.data ? apts.data.data.map(toApartment) : []),
    [apts.data],
  );
  const makeReady = useMemo(
    () => (mr.data ? mr.data.data.map(toMakeReady) : []),
    [mr.data],
  );
  const maintenance = useMemo(
    () => (maint.data ? maint.data.data.map(toMaintenanceTicket) : []),
    [maint.data],
  );
  const housekeeping = useMemo(
    () => (hk.data ? hk.data.data.map(toHousekeepingTicket) : []),
    [hk.data],
  );

  return { apartments, makeReady, maintenance, housekeeping, isUsingFixture: false };
}
