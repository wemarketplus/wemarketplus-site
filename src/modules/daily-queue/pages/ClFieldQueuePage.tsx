import { PAGE_TITLE } from '@/shared/ui/core/typography';
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { ClipboardList, Sparkles, Wrench } from 'lucide-react';
import {
  HOUSEKEEPING_STATUS_LABELS,
  HOUSEKEEPING_STATUS_PILL,
  MAINTENANCE_STATUS_LABELS,
  MAINTENANCE_STATUS_PILL,
  MAKE_READY_STATUS_LABELS,
  MAKE_READY_STATUS_PILL,
  TICKET_PRIORITY_LABELS,
  TICKET_PRIORITY_PILL,
} from '@/modules/cl-operations';
import {
  CL_HOUSEKEEPING_ROLES,
  CL_MAINTENANCE_ROLES,
  useRole,
} from '@/shared/rbac';
import { Card, CardContent } from '@/shared/ui/core';
import { Pill } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import { QueueSection } from '../components/QueueSection';
import { useGetClFieldQueueQuery } from '../api/dailyQueueApi';

/** One tappable row. Every item links to the board that owns the record. */
function Row({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link
      to={to}
      className="flex items-center gap-3 px-6 py-3 text-sm transition-colors hover:bg-primary/[0.04]"
    >
      {children}
    </Link>
  );
}

/** "Due 12 Aug" / "No due date" — a dateless task is still mine, just undated. */
const dueLabel = (dueDate: string | null): string =>
  dueDate ? `Due ${formatDate(dueDate)}` : 'No due date';

/**
 * My Queue — the CommunityLink field technician's landing screen.
 *
 * "Check My Queue first thing — it shows today's assigned tickets." That is the
 * whole brief, and the reason this is not the Dashboard: the CommunityLink
 * dashboard is a tenant sales roll-up (leads, tours, conversion), every tile of
 * which links into a screen a Maintenance or Housekeeping user cannot open.
 *
 * SECTIONS FOLLOW THE ROLE, not the response. The server omits tickets for
 * Housekeeping and housekeeping tasks for Maintenance, so keying off
 * `array.length === 0` would render "you are all caught up" about a board the
 * reader has no access to — the one lie a queue must not tell. QueueSection
 * deliberately renders empty sections and says so (see that component), which only
 * works if every section shown is one the reader could actually have work in.
 *
 * ROWS LINK OUT, like the sales queue: a queue is a to-do list, not a place to
 * work. Listing a ticket here exists to get the technician into Maintenance
 * Tickets with it, where the status dropdown and the ticket form live.
 */
export function ClFieldQueuePage() {
  const { isAny } = useRole();
  const { data, isLoading, isError, refetch } = useGetClFieldQueueQuery();

  const worksTickets = isAny(CL_MAINTENANCE_ROLES);
  const worksHousekeeping = isAny(CL_HOUSEKEEPING_ROLES);

  if (isError) {
    return (
      <Card>
        <CardContent className="px-6 py-8 text-sm text-muted">
          We could not load your queue right now.{' '}
          <button type="button" onClick={() => refetch()} className="underline">
            Try again
          </button>
          .
        </CardContent>
      </Card>
    );
  }

  if (isLoading || !data) {
    return (
      <Card>
        <CardContent className="px-6 py-8 text-sm text-muted">
          Loading your queue…
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-1">
        <h1 className={PAGE_TITLE}>My queue</h1>
        <p className="text-sm text-muted">
          {data.totalItems === 0
            ? 'Nothing is assigned to you right now — you are clear.'
            : `${data.totalItems} item${data.totalItems === 1 ? '' : 's'} assigned to you`}
          {' · '}
          {formatDate(data.date)}
        </p>
      </header>

      {worksTickets && (
        <QueueSection
          title="My maintenance tickets"
          subtitle="Open tickets assigned to you — most urgent first"
          icon={Wrench}
          count={data.maintenanceTickets.length}
          emptyLabel="No open tickets are assigned to you."
          urgent
        >
          {data.maintenanceTickets.map((ticket) => (
            <Row key={ticket.id} to="/operations/maintenance">
              <span className="min-w-0 flex-1">
                <span className="block font-semibold text-foreground">
                  {ticket.issue}
                </span>
                <span className="block text-[11px] text-muted">
                  {ticket.ticketNumber ?? 'No ticket number'}
                  {ticket.reporterName ? ` · ${ticket.reporterName}` : ''}
                </span>
              </span>
              <Pill tone={TICKET_PRIORITY_PILL[ticket.priority]}>
                {TICKET_PRIORITY_LABELS[ticket.priority]}
              </Pill>
              <Pill tone={MAINTENANCE_STATUS_PILL[ticket.status]}>
                {MAINTENANCE_STATUS_LABELS[ticket.status]}
              </Pill>
            </Row>
          ))}
        </QueueSection>
      )}

      {/* Make-ready is the shared handoff board — both field roles work it, so this
          section has no role condition. */}
      <QueueSection
        title="My make-ready tasks"
        subtitle="Units being prepped for a move-in — oldest due date first"
        icon={ClipboardList}
        count={data.makeReadyTasks.length}
        emptyLabel="No make-ready tasks are due for you."
      >
        {data.makeReadyTasks.map((task) => (
          <Row key={task.id} to="/operations/make-ready">
            <span className="min-w-0 flex-1">
              <span className="block font-semibold text-foreground">
                {task.taskName}
              </span>
              <span className="block text-[11px] text-muted">
                {dueLabel(task.dueDate)}
              </span>
            </span>
            <Pill tone={MAKE_READY_STATUS_PILL[task.status]}>
              {MAKE_READY_STATUS_LABELS[task.status]}
            </Pill>
          </Row>
        ))}
      </QueueSection>

      {worksHousekeeping && (
        <QueueSection
          title="My housekeeping tasks"
          subtitle="Cleaning assigned to you and due — oldest due date first"
          icon={Sparkles}
          count={data.housekeepingTasks.length}
          emptyLabel="No housekeeping tasks are due for you."
        >
          {data.housekeepingTasks.map((task) => (
            <Row key={task.id} to="/operations/housekeeping">
              <span className="min-w-0 flex-1">
                <span className="block font-semibold text-foreground">
                  {task.taskType}
                </span>
                <span className="block text-[11px] text-muted">
                  {task.area ? `${task.area} · ` : ''}
                  {dueLabel(task.dueDate)}
                </span>
              </span>
              <Pill tone={HOUSEKEEPING_STATUS_PILL[task.status]}>
                {HOUSEKEEPING_STATUS_LABELS[task.status]}
              </Pill>
            </Row>
          ))}
        </QueueSection>
      )}
    </div>
  );
}
