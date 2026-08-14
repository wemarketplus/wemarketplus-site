import { Card, CardContent } from '@/shared/ui/core';
import { SectionHeader } from '@/shared/ui/data-display';
import type { DashboardOperations } from '../types/dashboardTypes';
import { DashboardCardAction } from './DashboardCardAction';
import { PortfolioMetricRow } from './PortfolioMetricRow';

/**
 * "Maintenance" — step 4: "Click View on the Maintenance card for a quick read on
 * open tickets, WITHOUT NEEDING TO MANAGE THEM YOURSELF."
 *
 * That last clause is why this card is three counts and a link, and not the
 * Operations Alerts panel the Executive Dashboard gets. Alerts is a work queue with
 * an action per row ("assign this ticket") aimed at whoever clears it; an owner
 * wants to know whether the building is being looked after, then move on. Handing
 * them somebody else's to-do list is the opposite of an at-a-glance portfolio view.
 *
 * Only rendered when the server sent `operations` — below CL Gold there is no
 * maintenance module and no tickets to read.
 */
export function PortfolioMaintenanceCard({
  operations,
}: {
  operations: DashboardOperations;
}) {
  const { openWorkOrders, urgentWorkOrders, openMakeReadyTasks } = operations;
  const settled = openWorkOrders - urgentWorkOrders;

  return (
    <Card>
      <CardContent className="pt-6">
        <SectionHeader
          title="Maintenance"
          subtitle={
            openWorkOrders > 0
              ? `${openWorkOrders} open ticket${openWorkOrders === 1 ? '' : 's'} across the community`
              : 'No open tickets'
          }
          actions={
            <DashboardCardAction
              to="/operations/maintenance"
              label="View"
              ariaLabel="View open maintenance tickets"
            />
          }
        />
        <div>
          <PortfolioMetricRow
            label="Urgent"
            detail={
              urgentWorkOrders > 0 ? 'Needs attention today' : 'Nothing urgent'
            }
            value={String(urgentWorkOrders)}
            tone={urgentWorkOrders > 0 ? 'negative' : 'positive'}
          />
          <PortfolioMetricRow
            label="Other open tickets"
            value={String(settled)}
            tone={settled > 0 ? 'caution' : 'positive'}
          />
          <PortfolioMetricRow
            label="Units in make-ready"
            detail={`${openMakeReadyTasks} open task${openMakeReadyTasks === 1 ? '' : 's'}`}
            value={String(operations.units.makeReady)}
            tone={operations.units.makeReady > 0 ? 'caution' : 'positive'}
            last
          />
        </div>
      </CardContent>
    </Card>
  );
}
