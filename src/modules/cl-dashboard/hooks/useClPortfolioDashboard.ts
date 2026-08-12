import { useMemo } from 'react';
import { useListClLeadsQuery } from '@/modules/cl-leads';
import {
  APARTMENT_STATUS,
  useListClApartmentsQuery,
  useListClMaintenanceQuery,
} from '@/modules/cl-operations';
import { useListClPaidReferralsQuery } from '@/modules/cl-referrals';
import {
  CL_DASHBOARD_FETCH_LIMIT,
  clMonthlyRevenue,
  clOccupancySnapshot,
  clPendingReferralFees,
  isHotClLead,
  isOpenClTicket,
  type ClOccupancySnapshot,
  type ClPendingFees,
} from '../utils/clDashboardMetrics';

export interface ClPortfolioDashboardData {
  occupancy: ClOccupancySnapshot;
  /** Rent from filled units, per month. */
  monthlyRevenue: number;
  pendingFees: ClPendingFees;
  hotLeads: number;
  openWorkOrders: number;
  /**
   * Rent NOT being collected because units sit empty — the guide's "dollars
   * you're leaving on the table from vacant units", summarised for the tile that
   * links into the full Revenue Leakage screen.
   */
  vacancyExposure: number;
  isLoading: boolean;
  isError: boolean;
}

/**
 * The Owner/Investor top row: "Occupancy Rate, Available Units, Monthly Revenue,
 * Pending Referral Fees, Hot Leads, and Open Work Orders."
 *
 * Maintenance is fetched read-only here on purpose — the guide is explicit that
 * the owner wants "a quick read on open tickets, without needing to manage them
 * yourself", so this dashboard counts them and links out, and never mutates.
 */
export function useClPortfolioDashboard(): ClPortfolioDashboardData {
  const apartments = useListClApartmentsQuery({
    page: 1,
    limit: CL_DASHBOARD_FETCH_LIMIT,
  });
  const maintenance = useListClMaintenanceQuery({
    page: 1,
    limit: CL_DASHBOARD_FETCH_LIMIT,
  });
  const paidReferrals = useListClPaidReferralsQuery({
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
  const referralRows = useMemo(
    () => paidReferrals.data?.data ?? [],
    [paidReferrals.data],
  );
  const leadRows = useMemo(() => leads.data?.data ?? [], [leads.data]);

  return useMemo(() => {
    const occupancy = clOccupancySnapshot(apartmentRows);
    /**
     * Exposure counts only AVAILABLE units. A unit on notice is still paying
     * this month and a make-ready unit is mid-turn by design; billing either as
     * lost revenue would inflate the figure with work that is going to plan.
     */
    const vacancyExposure = apartmentRows
      .filter((a) => a.status === APARTMENT_STATUS.Available)
      .reduce((sum, a) => sum + (a.monthlyRate ?? 0), 0);

    return {
      occupancy,
      monthlyRevenue: clMonthlyRevenue(apartmentRows),
      pendingFees: clPendingReferralFees(referralRows),
      hotLeads: leadRows.filter(isHotClLead).length,
      openWorkOrders: ticketRows.filter(isOpenClTicket).length,
      vacancyExposure,
      isLoading:
        apartments.isLoading ||
        maintenance.isLoading ||
        paidReferrals.isLoading ||
        leads.isLoading,
      isError:
        apartments.isError ||
        maintenance.isError ||
        paidReferrals.isError ||
        leads.isError,
    };
  }, [
    apartmentRows,
    referralRows,
    leadRows,
    ticketRows,
    apartments.isLoading,
    apartments.isError,
    maintenance.isLoading,
    maintenance.isError,
    paidReferrals.isLoading,
    paidReferrals.isError,
    leads.isLoading,
    leads.isError,
  ]);
}
