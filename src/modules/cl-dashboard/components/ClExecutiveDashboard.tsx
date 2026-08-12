import { useMemo } from 'react';
import { Building2, ClipboardList, DoorOpen, Flame, PieChart, Wrench } from 'lucide-react';
import { StatTile } from '@/shared/ui/data-display';
import { useClExecutiveDashboard } from '../hooks/useClExecutiveDashboard';
import { formatClPercent } from '../utils/clDashboardMetrics';
import { ClDashboardState } from './ClDashboardState';
import { ClOperationsAlerts, type ClOpsAlert } from './ClOperationsAlerts';

/**
 * The Executive Director's dashboard — "Occupancy %, Available Units, Make-Ready
 * count, On-Notice residents, Hot Leads, and Open Work Orders — all in one
 * screen", plus the Operations Alerts panel that turns each into an action.
 */
export function ClExecutiveDashboard() {
  const {
    occupancy,
    makeReadyUnits,
    openMakeReadyTasks,
    hotLeads,
    openWorkOrders,
    isLoading,
    isError,
  } = useClExecutiveDashboard();

  /**
   * Alerts are DERIVED from the same numbers the tiles show, so the panel can
   * never contradict the row above it. A condition that is healthy produces no
   * row at all — a permanent "0 open work orders" alert trains the director to
   * ignore the panel.
   */
  const alerts = useMemo<ClOpsAlert[]>(() => {
    const rows: ClOpsAlert[] = [];

    if (makeReadyUnits > 0) {
      rows.push({
        id: 'make-ready',
        label: `${makeReadyUnits} unit${makeReadyUnits === 1 ? '' : 's'} being turned`,
        detail:
          openMakeReadyTasks > 0
            ? `${openMakeReadyTasks} make-ready task${openMakeReadyTasks === 1 ? '' : 's'} still open`
            : 'No make-ready tasks logged yet — the turn has not been scheduled',
        // No tasks on a unit that is sitting in make_ready is the genuinely
        // urgent case: the unit is off the market and nobody has been assigned.
        urgent: openMakeReadyTasks === 0,
        actionLabel: 'Schedule make-ready',
        to: '/operations/make-ready',
      });
    }

    if (occupancy.onNotice > 0) {
      rows.push({
        id: 'on-notice',
        label: `${occupancy.onNotice} resident${occupancy.onNotice === 1 ? '' : 's'} on notice`,
        detail: 'Units coming available — start the turn and the tour pipeline',
        urgent: false,
        actionLabel: 'View occupancy',
        to: '/occupancy-overview',
      });
    }

    if (occupancy.available > 0) {
      rows.push({
        id: 'available',
        label: `${occupancy.available} unit${occupancy.available === 1 ? '' : 's'} available now`,
        detail: 'Ready to fill — match them against the current pipeline',
        urgent: false,
        actionLabel: 'View leads',
        to: '/leads',
      });
    }

    if (hotLeads > 0) {
      rows.push({
        id: 'hot-leads',
        label: `${hotLeads} hot lead${hotLeads === 1 ? '' : 's'} in the pipeline`,
        detail: 'Families flagged urgent and still deciding',
        urgent: true,
        actionLabel: 'View leads',
        to: '/leads',
      });
    }

    if (openWorkOrders > 0) {
      rows.push({
        id: 'work-orders',
        label: `${openWorkOrders} open work order${openWorkOrders === 1 ? '' : 's'}`,
        detail: 'Maintenance tickets not yet completed',
        urgent: false,
        actionLabel: 'View maintenance',
        to: '/operations/maintenance',
      });
    }

    return rows;
  }, [
    makeReadyUnits,
    openMakeReadyTasks,
    occupancy.onNotice,
    occupancy.available,
    hotLeads,
    openWorkOrders,
  ]);

  if (isLoading || isError) {
    return <ClDashboardState isError={isError} />;
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <StatTile
          label="Occupancy"
          value={formatClPercent(occupancy.rate)}
          hint={`${occupancy.occupied} of ${occupancy.total} units filled`}
          tone={occupancy.rate >= 0.9 ? 'g' : 'y'}
          icon={PieChart}
        />
        <StatTile
          label="Available units"
          value={String(occupancy.available)}
          hint="Ready to move in"
          tone="b"
          icon={DoorOpen}
        />
        <StatTile
          label="Make-ready"
          value={String(makeReadyUnits)}
          hint={`${openMakeReadyTasks} task${openMakeReadyTasks === 1 ? '' : 's'} open`}
          tone="y"
          icon={ClipboardList}
        />
        <StatTile
          label="On notice"
          value={String(occupancy.onNotice)}
          hint="Residents moving out"
          tone={occupancy.onNotice > 0 ? 'y' : 'g'}
          icon={Building2}
        />
        <StatTile
          label="Hot leads"
          value={String(hotLeads)}
          hint={hotLeads > 0 ? 'Needs attention today' : 'None flagged'}
          tone={hotLeads > 0 ? 'r' : 'g'}
          icon={Flame}
        />
        <StatTile
          label="Open work orders"
          value={String(openWorkOrders)}
          hint={openWorkOrders > 0 ? 'In the maintenance queue' : 'All clear'}
          tone={openWorkOrders > 0 ? 'r' : 'g'}
          icon={Wrench}
        />
      </div>

      <ClOperationsAlerts alerts={alerts} />
    </div>
  );
}
