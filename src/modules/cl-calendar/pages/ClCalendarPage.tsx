import { useTenantCalendarColors } from '@/modules/appointments';
import { Card, CardContent } from '@/shared/ui/core';
import { ClCalendarDayPanel } from '../components/ClCalendarDayPanel';
import { ClCalendarMonthGrid } from '../components/ClCalendarMonthGrid';
import { ClCalendarScopeToggle } from '../components/ClCalendarScopeToggle';
import { ScheduleClEventModal } from '../components/ScheduleClEventModal';
import { useClCalendar } from '../hooks/useClCalendar';
import { useClScheduleEvent } from '../hooks/useClScheduleEvent';

/**
 * The CommunityLink shared team calendar — the guide's "Your Shared Team
 * Calendar" section.
 *
 * CommunityLink had no calendar at all: /appointments is HospiceLink-scoped and
 * jobId-bound, so a marketer following "Click Calendar" found no such row. This
 * is that screen, over CommunityLink's own tours and outreach visits.
 *
 * Per-user colours come from the SAME palette and the same stored
 * `users.calendarColor` the HospiceLink calendar uses, which is what makes the
 * guide's "Change your own calendar color anytime from your profile settings"
 * true here too — that picker already exists in Settings and now drives this
 * screen as well.
 */
export function ClCalendarPage() {
  const calendar = useClCalendar();
  const schedule = useClScheduleEvent();

  const showOwnerColors = calendar.scope === 'all';
  // Only "All users" needs the tenant's colours; a personal calendar is one
  // person's rows, where a per-owner hue carries no information.
  const colors = useTenantCalendarColors(showOwnerColors);

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-3xl text-foreground">Calendar</h1>
          <p className="text-sm text-muted">
            Tours, facility visits and physician lunches — yours or the whole
            team's.
          </p>
        </div>
        <ClCalendarScopeToggle
          scope={calendar.scope}
          onChange={calendar.setScope}
          hasUnownedEvents={calendar.hasUnownedEvents}
        />
      </header>

      {calendar.isError ? (
        <Card>
          <CardContent className="px-6 py-8 text-sm text-muted">
            We could not load the calendar right now. Please try again in a
            moment.
          </CardContent>
        </Card>
      ) : calendar.isLoading ? (
        <Card>
          <CardContent className="px-6 py-8 text-sm text-muted">
            Loading the calendar…
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_320px]">
          <ClCalendarMonthGrid
            month={calendar.month}
            cells={calendar.cells}
            selectedKey={calendar.selectedKey}
            isFetching={calendar.isFetching}
            colors={colors}
            showOwnerColors={showOwnerColors}
            onPrevMonth={calendar.prevMonth}
            onNextMonth={calendar.nextMonth}
            onToday={calendar.goToday}
            onSelectDay={calendar.selectDay}
          />

          <ClCalendarDayPanel
            dayKey={calendar.selectedKey}
            events={calendar.selectedEvents}
            colors={colors}
            showOwnerColors={showOwnerColors}
            onSchedule={() => schedule.openFor(calendar.selectedKey)}
          />
        </div>
      )}

      <ScheduleClEventModal
        open={schedule.open}
        dayKey={schedule.dayKey}
        isSaving={schedule.isSaving}
        leadOptions={schedule.leadOptions}
        referralSourceOptions={schedule.referralSourceOptions}
        onClose={schedule.close}
        onSubmit={schedule.submit}
      />
    </div>
  );
}
