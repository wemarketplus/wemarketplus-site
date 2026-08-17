import type { DashboardOperations } from '../types/dashboardTypes';

export interface OperationsAlert {
  id: string;
  tone: 'destructive' | 'warning' | 'success';
  title: string;
  detail: string;
  /** The action button's label and destination. */
  actionLabel: string;
  to: string;
}

/**
 * The Executive Director's Operations Alerts, derived from live counts.
 *
 * Step 3 of the guide: "Use the Operations Alerts on your dashboard to jump
 * straight into action — buttons like 'Schedule Make-Ready' or 'View Leads' take
 * you right where you need to go." So every alert ends in exactly one button, and
 * that button goes to the screen where the work is done.
 *
 * DERIVED, NOT WRITTEN. The client's reference design hardcodes its three alerts
 * ("Unit 104 On-Notice", "Earl Davis moving out Feb 28") because it is a mockup.
 * Real alerts have to appear and disappear on their own, or a director learns to
 * ignore the panel — a permanent "2 Hot Leads" that never changes is worse than
 * no panel, because it looks like information.
 *
 * ORDERED BY WHAT DECAYS FASTEST, not by severity: an urgent work order and a
 * move-out are both bad, but only one of them is someone sitting without heat.
 * Hot leads come last of the four because a lead can wait an hour; a unit that is
 * not turned over cannot be sold at all.
 *
 * A QUIET COMMUNITY GETS AN EMPTY LIST, and the panel says so rather than
 * inventing a row. "Nothing needs you" is a real answer and the only one that
 * makes the non-empty case worth reading.
 *
 * Pure — no hooks, no formatting of anything the server already decided — so the
 * thresholds are testable and live in one place.
 */
export function buildOperationsAlerts(
  operations: DashboardOperations,
  hotLeads: number,
): OperationsAlert[] {
  const alerts: OperationsAlert[] = [];
  const { units, openWorkOrders, urgentWorkOrders, openMakeReadyTasks } =
    operations;

  if (urgentWorkOrders > 0) {
    alerts.push({
      id: 'urgent-work-orders',
      tone: 'destructive',
      title: `${urgentWorkOrders} urgent work order${urgentWorkOrders === 1 ? '' : 's'}`,
      detail:
        'Marked urgent and still open. These are the ones a resident is waiting on.',
      actionLabel: 'View maintenance',
      to: '/operations/maintenance',
    });
  }

  if (units.onNotice > 0) {
    alerts.push({
      id: 'on-notice',
      tone: 'warning',
      title: `${units.onNotice} unit${units.onNotice === 1 ? '' : 's'} on notice`,
      detail:
        units.onNotice === 1
          ? 'A resident is moving out. Get the turnover scheduled before it sits empty.'
          : 'Residents are moving out. Get the turnovers scheduled before they sit empty.',
      // The guide names this button explicitly.
      actionLabel: 'Schedule make-ready',
      to: '/operations/make-ready',
    });
  }

  if (units.makeReady > 0) {
    alerts.push({
      id: 'make-ready',
      tone: 'warning',
      title: `${units.makeReady} unit${units.makeReady === 1 ? '' : 's'} in make-ready`,
      detail: `${openMakeReadyTasks} task${openMakeReadyTasks === 1 ? '' : 's'} still open across the turnover board.`,
      actionLabel: 'View board',
      to: '/operations/make-ready',
    });
  }

  if (hotLeads > 0) {
    alerts.push({
      id: 'hot-leads',
      tone: 'success',
      title: `${hotLeads} hot lead${hotLeads === 1 ? '' : 's'}`,
      detail: 'Flagged urgent and still open — these need a call today.',
      // The guide's other named button.
      actionLabel: 'View leads',
      to: '/leads',
    });
  }

  // Deliberately AFTER the urgent branch and conditioned on it: a community with
  // urgent tickets has already been told about them, and a second, vaguer row
  // about the same queue would just push the actionable one down.
  if (urgentWorkOrders === 0 && openWorkOrders > 0) {
    alerts.push({
      id: 'open-work-orders',
      tone: 'warning',
      title: `${openWorkOrders} open work order${openWorkOrders === 1 ? '' : 's'}`,
      detail: 'None urgent, but the queue is not empty.',
      actionLabel: 'View maintenance',
      to: '/operations/maintenance',
    });
  }

  return alerts;
}
