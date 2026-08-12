import { useMemo } from 'react';
import { useListClLeadsQuery } from '@/modules/cl-leads';
import {
  useListClApartmentsQuery,
  useListClMaintenanceQuery,
  useListClMakeReadyQuery,
} from '@/modules/cl-operations';
import {
  CL_DASHBOARD_FETCH_LIMIT,
  clOccupancySnapshot,
  isHotClLead,
  isOpenClMakeReady,
  isOpenClTicket,
  type ClOccupancySnapshot,
} from '../utils/clDashboardMetrics';

export interface ClExecutiveDashboardData {
  occupancy: ClOccupancySnapshot;
  /** Units in the make-ready pipeline — the STATUS count, see the note below. */
  makeReadyUnits: number;
  /** Unfinished make-ready TASKS across those units. */
  openMakeReadyTasks: number;
  hotLeads: number;
  openWorkOrders: number;
  isLoading: boolean;
  isError: boolean;
}

/**
 * The Executive Director's one screen: "Occupancy %, Available Units, Make-Ready
 * count, On-Notice residents, Hot Leads, and Open Work Orders."
 *
 * "Make-Ready count" is deliberately the count of UNITS whose status is
 * make_ready, not the count of make-ready tasks — a director asking "how many
 * units are being turned?" wants units, and one unit routinely carries four
 * tasks. Both numbers are returned because the Operations Alerts panel needs the
 * task count to say whether the turn has actually started.
 */
export function useClExecutiveDashboard(): ClExecutiveDashboardData {
  const apartments = useListClApartmentsQuery({
    page: 1,
    limit: CL_DASHBOARD_FETCH_LIMIT,
  });
  const maintenance = useListClMaintenanceQuery({
    page: 1,
    limit: CL_DASHBOARD_FETCH_LIMIT,
  });
  const makeReady = useListClMakeReadyQuery({
    page: 1,
    limit: CL_DASHBOARD_FETCH_LIMIT,
  });
  const leads = useListClLeadsQuery({
    page: 1,
    limit: CL_DASHBOARD_FETCH_LIMIT,
  });

  const apartmentRows = useMemo(
    () => apartments.data?.data ?? [],
    [apartments.data],
  );
  const ticketRows = useMemo(
    () => maintenance.data?.data ?? [],
    [maintenance.data],
  );
  const makeReadyRows = useMemo(
    () => makeReady.data?.data ?? [],
    [makeReady.data],
  );
  const leadRows = useMemo(() => leads.data?.data ?? [], [leads.data]);

  const occupancy = useMemo(
    () => clOccupancySnapshot(apartmentRows),
    [apartmentRows],
  );

  return useMemo(
    () => ({
      occupancy,
      makeReadyUnits: occupancy.makeReady,
      openMakeReadyTasks: makeReadyRows.filter(isOpenClMakeReady).length,
      hotLeads: leadRows.filter(isHotClLead).length,
      openWorkOrders: ticketRows.filter(isOpenClTicket).length,
      isLoading:
        apartments.isLoading ||
        maintenance.isLoading ||
        makeReady.isLoading ||
        leads.isLoading,
      isError:
        apartments.isError ||
        maintenance.isError ||
        makeReady.isError ||
        leads.isError,
    }),
    [
      occupancy,
      makeReadyRows,
      leadRows,
      ticketRows,
      apartments.isLoading,
      apartments.isError,
      maintenance.isLoading,
      maintenance.isError,
      makeReady.isLoading,
      makeReady.isError,
      leads.isLoading,
      leads.isError,
    ],
  );
}
