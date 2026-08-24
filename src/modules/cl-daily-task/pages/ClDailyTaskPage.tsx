import { PAGE_TITLE } from '@/shared/ui/core/typography';
import { CalendarCheck, Clock, PhoneCall } from 'lucide-react';
import { QueueSection } from '@/modules/daily-queue';
import { ClQueueRow } from '@/modules/cl-dashboard';
import { Card, CardContent } from '@/shared/ui/core';
import { Pill } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import { CL_DAILY_TASK_MAX_ROWS } from '../constants/clDailyTaskConstants';
import { useClDailyTask } from '../hooks/useClDailyTask';

/**
 * "Check Daily Task (or your Dashboard) every morning. This list builds itself."
 *
 * Three sections, one per trigger the guide names. Every section renders even
 * when empty (see QueueSection): "nothing due" is a real answer a marketer should
 * be able to trust, and a screen that hides its empty sections looks the same
 * whether the day is clear or the feature has broken.
 */
export function ClDailyTaskPage() {
  const {
    followUpsDue,
    toursToday,
    goneQuiet,
    leadName,
    totalItems,
    isLoading,
    isError,
  } = useClDailyTask();

  if (isError) {
    return (
      <Card>
        <CardContent className="px-6 py-8 text-sm text-muted">
          We could not build your task list right now. Please try again in a
          moment.
        </CardContent>
      </Card>
    );
  }

  if (isLoading) {
    return (
      <Card>
        <CardContent className="px-6 py-8 text-sm text-muted">
          Building today's list…
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className={PAGE_TITLE}>Daily task</h1>
        <p className="text-sm text-muted">
          {totalItems === 0
            ? "Nothing needs you today — you're clear."
            : `${totalItems} thing${totalItems === 1 ? '' : 's'} need you today.`}
        </p>
      </header>

      <QueueSection
        title="Follow-ups due"
        subtitle="Families whose follow-up date has arrived or passed"
        icon={PhoneCall}
        count={followUpsDue.length}
        emptyLabel="No follow-ups due today."
        urgent
      >
        {followUpsDue.slice(0, CL_DAILY_TASK_MAX_ROWS).map(({ lead, daysOverdue }) => (
          <ClQueueRow
            key={lead.id}
            to="/leads"
            title={
              [lead.firstName, lead.lastName].filter(Boolean).join(' ').trim() ||
              'Unnamed lead'
            }
            detail={[lead.phone, lead.source && `via ${lead.source}`]
              .filter(Boolean)
              .join(' · ')}
            pills={
              <Pill tone={daysOverdue > 0 ? 'r' : 'y'}>
                {daysOverdue === 0
                  ? 'Due today'
                  : `${daysOverdue}d overdue`}
              </Pill>
            }
          />
        ))}
      </QueueSection>

      <QueueSection
        title="Tours today"
        subtitle="Booked tours on today's date"
        icon={CalendarCheck}
        count={toursToday.length}
        emptyLabel="No tours scheduled for today."
      >
        {toursToday.slice(0, CL_DAILY_TASK_MAX_ROWS).map((tour) => (
          <ClQueueRow
            key={tour.id}
            to="/tours"
            title={leadName(tour.leadId)}
            detail={tour.durationMin ? `${tour.durationMin} min tour` : 'Tour'}
            pills={
              <Pill tone="b">{formatDate(tour.scheduledAt, 'h:mm a')}</Pill>
            }
          />
        ))}
      </QueueSection>

      <QueueSection
        title="Gone quiet"
        subtitle="Open leads nobody has touched in a while"
        icon={Clock}
        count={goneQuiet.length}
        emptyLabel="Every open lead has been touched recently."
      >
        {goneQuiet.slice(0, CL_DAILY_TASK_MAX_ROWS).map(({ lead, daysQuiet }) => (
          <ClQueueRow
            key={lead.id}
            to="/leads"
            title={
              [lead.firstName, lead.lastName].filter(Boolean).join(' ').trim() ||
              'Unnamed lead'
            }
            detail={[lead.phone, lead.source && `via ${lead.source}`]
              .filter(Boolean)
              .join(' · ')}
            pills={<Pill tone="y">Quiet {daysQuiet}d</Pill>}
          />
        ))}
      </QueueSection>
    </div>
  );
}
