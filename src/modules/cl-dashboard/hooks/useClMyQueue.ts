import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
import {
  useListClHousekeepingQuery,
  useListClMaintenanceQuery,
  useListClMakeReadyQuery,
  type ClHousekeepingTaskRecord,
  type ClMaintenanceTicketRecord,
  type ClMakeReadyTaskRecord,
} from '@/modules/cl-operations';
import { Role } from '@/shared/rbac';
import {
  CL_DASHBOARD_FETCH_LIMIT,
  isOpenClHousekeeping,
  isOpenClMakeReady,
  isOpenClTicket,
} from '../utils/clDashboardMetrics';

export interface ClMyQueueData {
  /** Maintenance only — open tickets assigned to this user. */
  tickets: ClMaintenanceTicketRecord[];
  /** Housekeeping only — open cleaning tasks assigned to this user. */
  housekeeping: ClHousekeepingTaskRecord[];
  /** Both roles — the shared make-ready handoff board, their rows only. */
  makeReady: ClMakeReadyTaskRecord[];
  /** True when this user has nothing open at all. */
  isEmpty: boolean;
  /**
   * True when the queue is empty only because nothing is assigned to this user
   * — there IS open work on the board, just not theirs. Distinguishing the two
   * is the difference between "you're clear" and "nobody has assigned you
   * anything", which are very different mornings.
   */
  hasUnassignedWork: boolean;
  isLoading: boolean;
  isError: boolean;
}

/**
 * The field roles' morning screen — "Check My Queue first thing — it shows
 * today's assigned tickets."
 *
 * SELF-SCOPED CLIENT-SIDE, and that is a real limitation worth stating: the
 * cl/* list endpoints take no `assignedTo` filter, so this fetches the tenant's
 * open work and narrows to `assignedTo === me` here. The rows a maintenance tech
 * cannot act on are therefore still fetched, and the sampling caveat in
 * clDashboardMetrics applies — on a large tenant a tech's own ticket could fall
 * outside the fetched page and go missing from their queue. An `assignedTo`
 * query param on those endpoints is the fix; until it exists, Maintenance
 * Tickets (the full, paginated table) stays the authoritative list and this is
 * the shortcut.
 *
 * Which halves are fetched depends on the role: a maintenance tech never needs
 * the housekeeping board and vice versa, so the unused query is skipped rather
 * than fetched and thrown away.
 */
export function useClMyQueue(role: Role | null): ClMyQueueData {
  const userId = useAppSelector((s) => s.auth.user?.id ?? null);
  const isMaintenance = role === Role.Maintenance;
  const isHousekeeping = role === Role.Housekeeping;

  const maintenance = useListClMaintenanceQuery(
    { page: 1, limit: CL_DASHBOARD_FETCH_LIMIT },
    { skip: !isMaintenance },
  );
  const housekeeping = useListClHousekeepingQuery(
    { page: 1, limit: CL_DASHBOARD_FETCH_LIMIT },
    { skip: !isHousekeeping },
  );
  const makeReady = useListClMakeReadyQuery({
    page: 1,
    limit: CL_DASHBOARD_FETCH_LIMIT,
  });

  return useMemo(() => {
    const mine = <T extends { assignedTo: string | null }>(rows: readonly T[]) =>
      userId ? rows.filter((row) => row.assignedTo === userId) : [];

    const openTickets = (maintenance.data?.data ?? []).filter(isOpenClTicket);
    const openHousekeeping = (housekeeping.data?.data ?? []).filter(
      isOpenClHousekeeping,
    );
    const openMakeReady = (makeReady.data?.data ?? []).filter(isOpenClMakeReady);

    const tickets = mine(openTickets);
    const housekeepingMine = mine(openHousekeeping);
    const makeReadyMine = mine(openMakeReady);

    const openTotal =
      openTickets.length + openHousekeeping.length + openMakeReady.length;
    const mineTotal =
      tickets.length + housekeepingMine.length + makeReadyMine.length;

    return {
      tickets,
      housekeeping: housekeepingMine,
      makeReady: makeReadyMine,
      isEmpty: mineTotal === 0,
      hasUnassignedWork: mineTotal === 0 && openTotal > 0,
      isLoading:
        maintenance.isLoading || housekeeping.isLoading || makeReady.isLoading,
      isError: maintenance.isError || housekeeping.isError || makeReady.isError,
    };
  }, [
    userId,
    maintenance.data,
    maintenance.isLoading,
    maintenance.isError,
    housekeeping.data,
    housekeeping.isLoading,
    housekeeping.isError,
    makeReady.data,
    makeReady.isLoading,
    makeReady.isError,
  ]);
}
