import { ClipboardList, Sparkles, Wrench } from 'lucide-react';
import { QueueSection } from '@/modules/daily-queue';
import {
  MAINTENANCE_STATUS_LABELS,
  MAINTENANCE_STATUS_PILL,
  MAKE_READY_STATUS_LABELS,
  MAKE_READY_STATUS_PILL,
  HOUSEKEEPING_STATUS_LABELS,
  HOUSEKEEPING_STATUS_PILL,
  TICKET_PRIORITY_LABELS,
  TICKET_PRIORITY_PILL,
} from '@/modules/cl-operations';
import { Card, CardContent } from '@/shared/ui/core';
import { Pill } from '@/shared/ui/data-display';
import { Role } from '@/shared/rbac';
import { formatDate } from '@/shared/utils/dateFormatter';
import { useClMyQueue } from '../hooks/useClMyQueue';
import { ClDashboardState } from './ClDashboardState';
import { ClQueueRow } from './ClQueueRow';

/**
 * "My Queue" — the Maintenance and Housekeeping dashboard.
 *
 * Their sidebars carry nothing else (the demos give both roles a single MY WORK
 * group), so this screen is their whole morning: what is assigned to them,
 * grouped the way their guide names it, with every row linking to the full
 * screen where they can actually update status.
 *
 * Read-only by design. The guide's update instruction is "Click Update on any
 * ticket to change its status", which is the Maintenance Tickets / Housekeeping
 * Tasks table — putting a second status control here would let the same ticket be
 * advanced from two places with different validation.
 */
export function ClMyQueuePanel({ role }: { role: Role | null }) {
  const {
    tickets,
    housekeeping,
    makeReady,
    isEmpty,
    hasUnassignedWork,
    isLoading,
    isError,
  } = useClMyQueue(role);

  if (isLoading || isError) {
    return <ClDashboardState isError={isError} />;
  }

  const isHousekeeping = role === Role.Housekeeping;

  return (
    <div className="space-y-4">
      {/* Says which of the two empty states this is — see useClMyQueue. */}
      {isEmpty && (
        <Card>
          <CardContent className="flex items-center gap-3 px-6 py-5">
            <span className="rounded-md bg-success/[0.10] p-2 text-success">
              <Sparkles className="h-4 w-4" />
            </span>
            <p className="text-[13px] text-muted">
              {hasUnassignedWork
                ? 'Nothing is assigned to you yet — there is open work on the board waiting to be assigned.'
                : 'Your queue is clear. Nothing is assigned to you right now.'}
            </p>
          </CardContent>
        </Card>
      )}

      {!isHousekeeping && (
        <QueueSection
          title="My tickets"
          subtitle="Maintenance work orders assigned to you"
          icon={Wrench}
          count={tickets.length}
          emptyLabel="No open tickets assigned to you."
          urgent
        >
          {tickets.map((ticket) => (
            <ClQueueRow
              key={ticket.id}
              to="/operations/maintenance"
              title={ticket.issue}
              detail={[
                ticket.ticketNumber,
                ticket.reporterName && `Reported by ${ticket.reporterName}`,
              ]
                .filter(Boolean)
                .join(' · ')}
              pills={
                <>
                  <Pill tone={TICKET_PRIORITY_PILL[ticket.priority]}>
                    {TICKET_PRIORITY_LABELS[ticket.priority]}
                  </Pill>
                  <Pill tone={MAINTENANCE_STATUS_PILL[ticket.status]}>
                    {MAINTENANCE_STATUS_LABELS[ticket.status]}
                  </Pill>
                </>
              }
            />
          ))}
        </QueueSection>
      )}

      {isHousekeeping && (
        <QueueSection
          title="My cleaning tasks"
          subtitle="Housekeeping work assigned to you"
          icon={ClipboardList}
          count={housekeeping.length}
          emptyLabel="No open cleaning tasks assigned to you."
          urgent
        >
          {housekeeping.map((task) => (
            <ClQueueRow
              key={task.id}
              to="/operations/housekeeping"
              title={task.taskType}
              detail={[
                task.area,
                task.dueDate && `Due ${formatDate(task.dueDate, 'MMM d')}`,
              ]
                .filter(Boolean)
                .join(' · ')}
              pills={
                <Pill tone={HOUSEKEEPING_STATUS_PILL[task.status]}>
                  {HOUSEKEEPING_STATUS_LABELS[task.status]}
                </Pill>
              }
            />
          ))}
        </QueueSection>
      )}

      <QueueSection
        title={isHousekeeping ? 'Make-ready clean' : 'Make-ready tasks'}
        subtitle="Units being prepped for a new move-in"
        icon={ClipboardList}
        count={makeReady.length}
        emptyLabel="No make-ready work assigned to you."
      >
        {makeReady.map((task) => (
          <ClQueueRow
            key={task.id}
            to="/operations/make-ready"
            title={task.taskName}
            detail={task.dueDate ? `Due ${formatDate(task.dueDate, 'MMM d')}` : ''}
            pills={
              <Pill tone={MAKE_READY_STATUS_PILL[task.status]}>
                {MAKE_READY_STATUS_LABELS[task.status]}
              </Pill>
            }
          />
        ))}
      </QueueSection>
    </div>
  );
}
