import { Link } from 'react-router-dom';
import { CalendarCheck, ListChecks, MoonStar } from 'lucide-react';
import { Card, CardContent } from '@/shared/ui/core';
import { Pill } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import {
  LEAD_STAGE_LABELS,
  STAGE_PILL,
  URGENCY_LABELS,
  URGENCY_PILL,
} from '@/modules/cl-leads/constants/leadsConstants';
import { QueueSection } from '../components/QueueSection';
import { useGetClDailyQueueQuery } from '../api/dailyQueueApi';
import type { ClDailyQueue } from '../types/dailyQueueTypes';

const leadName = (l: { firstName: string; lastName: string | null }): string =>
  [l.firstName, l.lastName].filter(Boolean).join(' ').trim() || 'Lead';

const timeOf = (iso: string): string =>
  new Date(iso).toLocaleTimeString(undefined, {
    hour: 'numeric',
    minute: '2-digit',
  });

/** One tappable row. Every item in this queue is a lead or a tour, so both link out. */
function Row({ to, children }: { to: string; children: React.ReactNode }) {
  return (
    <Link
      to={to}
      className="flex items-center gap-3 px-6 py-3 text-sm transition-colors hover:bg-primary/[0.04]"
    >
      {children}
    </Link>
  );
}

/**
 * Daily Task, CommunityLink.
 *
 * "This list builds itself — a lead's follow-up date arriving, a tour scheduled
 * for today, or a lead that's gone quiet too long all show up automatically."
 * Those three sentences are the three sections, in that order.
 *
 * Reuses QueueSection from the HospiceLink queue rather than restyling: the two
 * screens are the same idea for two products, and a section that renders even when
 * empty (saying so) is the behaviour that makes "nothing to do" trustworthy — see
 * that component for the argument.
 *
 * Every row LINKS OUT to the screen that owns the record. A queue is a to-do list,
 * not a place to work: the point of listing a lead here is to get the marketer into
 * the Lead Pipeline with it.
 */
export function ClDailyTasksPage() {
  const { data, isLoading, isError, refetch } = useGetClDailyQueueQuery();

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

  if (isLoading || !data) {
    return (
      <Card>
        <CardContent className="px-6 py-8 text-sm text-muted">
          Loading your day…
        </CardContent>
      </Card>
    );
  }

  const queue: ClDailyQueue = data;

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-1">
        <h1 className="font-display text-3xl text-foreground">Daily tasks</h1>
        <p className="text-sm text-muted">
          {queue.totalItems === 0
            ? 'Nothing needs you today — you are clear.'
            : `${queue.totalItems} item${queue.totalItems === 1 ? '' : 's'} need you today`}
          {' · '}
          {formatDate(queue.date)}
        </p>
      </header>

      <QueueSection
        title="Follow-ups due"
        subtitle="Leads whose follow-up date has arrived — oldest first"
        icon={ListChecks}
        count={queue.followUpsDue.length}
        emptyLabel="No follow-ups are due. Every dated lead is still in the future."
        urgent
      >
        {queue.followUpsDue.map((lead) => (
          <Row key={lead.id} to="/leads">
            <span className="min-w-0 flex-1">
              <span className="block font-semibold text-foreground">
                {leadName(lead)}
              </span>
              <span className="block text-[11px] text-muted">
                Due {lead.followUpDate ? formatDate(lead.followUpDate) : '—'}
                {lead.source ? ` · ${lead.source}` : ''}
              </span>
            </span>
            <Pill tone={URGENCY_PILL[lead.urgency]}>
              {URGENCY_LABELS[lead.urgency]}
            </Pill>
            <Pill tone={STAGE_PILL[lead.stage]}>
              {LEAD_STAGE_LABELS[lead.stage]}
            </Pill>
          </Row>
        ))}
      </QueueSection>

      <QueueSection
        title="Tours today"
        subtitle="Still scheduled for today — earliest first"
        icon={CalendarCheck}
        count={queue.toursToday.length}
        emptyLabel="No tours are booked for today."
      >
        {queue.toursToday.map((tour) => (
          <Row key={tour.id} to="/tours">
            <span className="min-w-0 flex-1">
              <span className="block font-semibold text-foreground">
                {timeOf(tour.scheduledAt)}
                {tour.durationMin ? ` · ${tour.durationMin} min` : ''}
              </span>
              <span className="block text-[11px] text-muted">
                {tour.outcome ?? 'Community tour'}
              </span>
            </span>
            {/* The confirmation state is the reason to look at this row before
                lunch: a pending tour is the one worth a reminder call. */}
            {tour.confirmedAt ? (
              <Pill tone="g">Confirmed</Pill>
            ) : (
              <Pill tone="y">Pending</Pill>
            )}
          </Row>
        ))}
      </QueueSection>

      <QueueSection
        title="Gone quiet"
        subtitle="Active leads with no activity for two weeks and no follow-up booked"
        icon={MoonStar}
        count={queue.quietLeads.length}
        emptyLabel="Nothing has gone quiet. Every open lead has been touched recently."
      >
        {queue.quietLeads.map((lead) => (
          <Row key={lead.id} to="/leads">
            <span className="min-w-0 flex-1">
              <span className="block font-semibold text-foreground">
                {leadName(lead)}
              </span>
              <span className="block text-[11px] text-muted">
                Last activity {formatDate(lead.updatedAt)}
                {lead.source ? ` · ${lead.source}` : ''}
              </span>
            </span>
            <Pill tone={STAGE_PILL[lead.stage]}>
              {LEAD_STAGE_LABELS[lead.stage]}
            </Pill>
          </Row>
        ))}
      </QueueSection>
    </div>
  );
}
