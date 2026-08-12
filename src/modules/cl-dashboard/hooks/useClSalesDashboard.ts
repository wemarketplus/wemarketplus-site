import { useMemo } from 'react';
import { useListClLeadsQuery, type ClLeadRecord } from '@/modules/cl-leads';
import { useListClToursQuery, type ClTourRecord } from '@/modules/cl-tours';
import {
  CL_DASHBOARD_FETCH_LIMIT,
  hotClLeads,
  isOpenClLead,
  upcomingClTours,
} from '../utils/clDashboardMetrics';

export interface ClSalesDashboardData {
  /** Open pipeline rows — the guide's "Active Leads". */
  activeLeads: number;
  /** Urgent open leads, soonest follow-up first. The list worked top-down. */
  hotLeads: ClLeadRecord[];
  /** Booked tours still ahead. */
  upcomingTours: ClTourRecord[];
  isLoading: boolean;
  isError: boolean;
}

/**
 * The Sales Marketer's morning screen: "Your Sales Dashboard shows Active Leads,
 * Hot Leads, and Tours Scheduled — check the Hot Leads list first."
 *
 * Two list queries rather than a dashboard endpoint (see clDashboardMetrics for
 * why, including the one-page sampling caveat these counts inherit).
 */
export function useClSalesDashboard(): ClSalesDashboardData {
  const leads = useListClLeadsQuery({ page: 1, limit: CL_DASHBOARD_FETCH_LIMIT });
  const tours = useListClToursQuery({ page: 1, limit: CL_DASHBOARD_FETCH_LIMIT });

  const leadRows = useMemo(() => leads.data?.data ?? [], [leads.data]);
  const tourRows = useMemo(() => tours.data?.data ?? [], [tours.data]);

  return useMemo(
    () => ({
      activeLeads: leadRows.filter(isOpenClLead).length,
      hotLeads: hotClLeads(leadRows),
      upcomingTours: upcomingClTours(tourRows),
      isLoading: leads.isLoading || tours.isLoading,
      isError: leads.isError || tours.isError,
    }),
    [
      leadRows,
      tourRows,
      leads.isLoading,
      leads.isError,
      tours.isLoading,
      tours.isError,
    ],
  );
}
