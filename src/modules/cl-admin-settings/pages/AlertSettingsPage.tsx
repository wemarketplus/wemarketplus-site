import { AlertRoutingPanel } from '../components/AlertRoutingPanel';

/**
 * CommunityLink's Alert settings screen (Admin/Owner, CL Max).
 *
 * The controls themselves live in AlertRoutingPanel, which HospiceLink renders
 * as the "Alerts" tab on the Notifications page instead — the two products put
 * the same capability in different places, so the capability is a component and
 * each product supplies its own frame.
 */
export function AlertSettingsPage() {
  return (
    <div className="space-y-6">
      <header>
        <h1 className="font-display text-3xl text-foreground">Alert settings</h1>
        <p className="text-sm text-muted">Who gets notified, and how, for each event.</p>
      </header>

      <AlertRoutingPanel />
    </div>
  );
}
