import { CalendarCheck, Flame, Users } from 'lucide-react';
import { StatTile } from '@/shared/ui/data-display';
import { useClSalesDashboard } from '../hooks/useClSalesDashboard';
import { ClDashboardState } from './ClDashboardState';
import { ClHotLeadsPanel } from './ClHotLeadsPanel';

/**
 * The Sales Marketer's dashboard, exactly the three figures the guide names:
 * "Active Leads, Hot Leads, and Tours Scheduled — check the Hot Leads list
 * first, since those need attention today."
 *
 * The Hot Leads LIST, not just its count, is the point of this screen — the
 * guide sends the marketer here to work it, so the tiles are the summary and the
 * panel below is the job.
 */
export function ClSalesDashboard() {
  const { activeLeads, hotLeads, upcomingTours, isLoading, isError } =
    useClSalesDashboard();

  if (isLoading || isError) {
    return <ClDashboardState isError={isError} />;
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <StatTile
          label="Active leads"
          value={String(activeLeads)}
          hint="Families still being worked"
          tone="b"
          icon={Users}
        />
        <StatTile
          label="Hot leads"
          value={String(hotLeads.length)}
          hint={hotLeads.length > 0 ? 'Needs attention today' : 'None flagged'}
          tone={hotLeads.length > 0 ? 'r' : 'g'}
          icon={Flame}
        />
        <StatTile
          label="Tours scheduled"
          value={String(upcomingTours.length)}
          hint="Booked and still ahead"
          tone="y"
          icon={CalendarCheck}
        />
      </div>

      <ClHotLeadsPanel leads={hotLeads} />
    </div>
  );
}
