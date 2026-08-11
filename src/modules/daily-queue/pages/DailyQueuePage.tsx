import {
  CalendarCheck,
  ClipboardList,
  Heart,
  Pin,
  RotateCcw,
} from 'lucide-react';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { Pill } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import { JOB_TYPE_LABELS, JOB_PRIORITY_PILL } from '@/modules/jobs/constants/jobsConstants';
import { APPOINTMENT_TYPE_LABELS } from '@/modules/appointments/constants/appointmentsConstants';
import { MyPerformancePanel } from '@/modules/intelligence';
import { HL_MARKETING_ROLES, useRole } from '@/shared/rbac';
import { QueueSection } from '../components/QueueSection';
import { useDailyQueue } from '../hooks/useDailyQueue';

/** `YYYY-MM-DD` — the queue's own date, compared as a string, not an instant. */
const isOverdue = (dueDate: string | null, today: string): boolean =>
  dueDate !== null && dueDate < today;

const timeOf = (iso: string): string =>
  new Date(iso).toLocaleTimeString(undefined, {
    hour: 'numeric',
    minute: '2-digit',
  });

export function DailyQueuePage() {
  const { queue, isLoading, isError, isFetching, refetch, completeTask, completingId } =
    useDailyQueue();
  /**
   * Three of the five sections below — field work, cold accounts, re-engagement —
   * are ACCOUNT-level marketing work, computed from prospects and referral sources
   * that Nurse and Caregiver are 403ed from. The daily queue is self-scoped, so it
   * correctly returns empty arrays for them, and the result was that the screen the
   * product guide calls their first stop of the day was 60% permanently blank
   * scaffolding: "No field work due", "Every account you own has been touched
   * recently", "No prospects have gone quiet" — none of which will ever say
   * anything else for a clinician.
   *
   * Hidden, not emptied: the sections stay exactly as they are for the marketing
   * roles they were built for.
   */
  const showMarketingWork = useRole().isAny(HL_MARKETING_ROLES);

  if (isError) {
    return (
      <Card>
        <CardContent className="px-6 py-8 text-sm text-muted">
          We could not load your tasks right now.{' '}
          <button type="button" onClick={() => refetch()} className="underline">
            Try again
          </button>
          .
        </CardContent>
      </Card>
    );
  }

  if (isLoading || !queue) {
    return (
      <Card>
        <CardContent className="px-6 py-8 text-sm text-muted">
          Loading your day…
        </CardContent>
      </Card>
    );
  }

  const today = queue.date;

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="font-display text-3xl text-foreground">Daily tasks</h1>
          <p className="text-sm text-muted">
            {queue.totalItems === 0
              ? 'Nothing outstanding — you are clear for today.'
              : `${queue.totalItems} ${queue.totalItems === 1 ? 'item' : 'items'} need${queue.totalItems === 1 ? 's' : ''} you today`}
          </p>
        </div>
        <Button
          variant="ghost"
          onClick={() => refetch()}
          disabled={isFetching}
        >
          <RotateCcw className="h-4 w-4" />
          {isFetching ? 'Refreshing…' : 'Refresh'}
        </Button>
      </header>

      {/* Standing first: the marketer's own numbers frame the work below. Reads a
          marketing-only endpoint, so it is skipped for clinical roles rather than
          firing a 403 and self-hiding on error. */}
      {showMarketingWork && <MyPerformancePanel />}

      <QueueSection
        title="Follow-ups due"
        subtitle="Reminders from your notes and visits"
        icon={Pin}
        count={queue.tasksDue.length}
        emptyLabel="No follow-ups due."
        urgent
      >
        <ul className="divide-y divide-border">
          {queue.tasksDue.map((task) => (
            <li key={task.id} className="flex flex-wrap items-center gap-3 px-6 py-3">
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold text-foreground">
                  {task.title}
                </p>
                <p className="text-[11px] text-muted-soft">
                  {task.dueDate ? formatDate(task.dueDate) : 'No due date'}
                  {isOverdue(task.dueDate, today) && (
                    <span className="ml-1 text-destructive">· overdue</span>
                  )}
                </p>
              </div>
              <Button
                variant="ghost"
                disabled={completingId === task.id}
                onClick={() => completeTask(task.id)}
              >
                {completingId === task.id ? 'Saving…' : 'Complete'}
              </Button>
            </li>
          ))}
        </ul>
      </QueueSection>

      {showMarketingWork && (
        <QueueSection
          title="Field work due"
          subtitle="Work the pipeline created when a prospect moved stage"
          icon={ClipboardList}
          count={queue.jobsDue.length}
          emptyLabel="No field work due."
          urgent
        >
          <ul className="divide-y divide-border">
            {queue.jobsDue.map((job) => (
              <li key={job.id} className="flex flex-wrap items-center gap-3 px-6 py-3">
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-foreground">
                    {job.objective ?? JOB_TYPE_LABELS[job.jobType]}
                  </p>
                  <p className="text-[11px] text-muted-soft">
                    {JOB_TYPE_LABELS[job.jobType]}
                    {job.dueDate && ` · due ${formatDate(job.dueDate)}`}
                    {isOverdue(job.dueDate, today) && (
                      <span className="ml-1 text-destructive">· overdue</span>
                    )}
                  </p>
                </div>
                <Pill tone={JOB_PRIORITY_PILL[job.priority]}>{job.priority}</Pill>
              </li>
            ))}
          </ul>
        </QueueSection>
      )}

      <QueueSection
        title="Today's visits"
        subtitle="What is already on your calendar"
        icon={CalendarCheck}
        count={queue.appointmentsToday.length}
        emptyLabel="Nothing scheduled today."
      >
        <ul className="divide-y divide-border">
          {queue.appointmentsToday.map((appointment) => (
            <li key={appointment.id} className="flex flex-wrap items-center gap-3 px-6 py-3">
              <span className="text-xs font-semibold tabular-nums text-primary">
                {timeOf(appointment.startAt)}
              </span>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold text-foreground">
                  {appointment.title}
                </p>
                <p className="text-[11px] text-muted-soft">
                  {APPOINTMENT_TYPE_LABELS[appointment.appointmentType]}
                  {appointment.location && ` · ${appointment.location}`}
                </p>
              </div>
            </li>
          ))}
        </ul>
      </QueueSection>

      {showMarketingWork && (
        <QueueSection
          title="Accounts going cold"
          subtitle="No visit or call logged in 14 days"
          icon={Heart}
          count={queue.coldReferralSources.length}
          emptyLabel="Every account you own has been touched recently."
          urgent
        >
          <ul className="divide-y divide-border">
            {queue.coldReferralSources.map((source) => (
              <li key={source.id} className="flex flex-wrap items-center gap-3 px-6 py-3">
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-foreground">
                    {source.name}
                  </p>
                  <p className="text-[11px] text-muted-soft">
                    {source.lastInteractionAt
                      ? `Last touched ${source.daysSinceLastInteraction} days ago`
                      : 'Never contacted'}
                  </p>
                </div>
                <Pill tone="r">Cold</Pill>
              </li>
            ))}
          </ul>
        </QueueSection>
      )}

      {showMarketingWork && (
        <QueueSection
          title="Re-engagement"
          subtitle="Open referrals with no activity for 30 days"
          icon={RotateCcw}
          count={queue.reengagementProspects.length}
          emptyLabel="No prospects have gone quiet."
          urgent
        >
          <ul className="divide-y divide-border">
            {queue.reengagementProspects.map((row) => (
              <li
                key={row.prospect.id}
                className="flex flex-wrap items-center gap-3 px-6 py-3"
              >
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-foreground">
                    {row.prospect.patientName}
                  </p>
                  <p className="text-[11px] text-muted-soft">
                    Quiet for {row.daysInactive} days · last activity{' '}
                    {formatDate(row.lastActivityAt)}
                  </p>
                </div>
                <Pill tone="y">{row.prospect.stage.replace(/_/g, ' ')}</Pill>
              </li>
            ))}
          </ul>
        </QueueSection>
      )}
    </div>
  );
}
