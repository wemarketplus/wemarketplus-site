import { useMemo } from 'react';
import {
  APARTMENTS_FIXTURE,
  HOUSEKEEPING_FIXTURE,
  MAINTENANCE_FIXTURE,
  MAKE_READY_FIXTURE,
} from '@/shared/fixtures';
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
    () => (apts.data && apts.data.data.length > 0 ? apts.data.data.map(toApartment) : APARTMENTS_FIXTURE),
    [apts.data],
  );
  const makeReady = useMemo(
    () => (mr.data && mr.data.data.length > 0 ? mr.data.data.map(toMakeReady) : MAKE_READY_FIXTURE),
    [mr.data],
  );
  const maintenance = useMemo(
    () => (maint.data && maint.data.data.length > 0 ? maint.data.data.map(toMaintenanceTicket) : MAINTENANCE_FIXTURE),
    [maint.data],
  );
  const housekeeping = useMemo(
    () => (hk.data && hk.data.data.length > 0 ? hk.data.data.map(toHousekeepingTicket) : HOUSEKEEPING_FIXTURE),
    [hk.data],
  );

  const live = Boolean(apts.data || mr.data || maint.data || hk.data);

  return { apartments, makeReady, maintenance, housekeeping, isUsingFixture: !live };
}
