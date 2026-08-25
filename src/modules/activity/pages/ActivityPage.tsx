import { PAGE_TITLE } from '@/shared/ui/core/typography';
import { useActivityPage } from '../hooks/useActivityPage';
import { ActivityTabs } from '../components/ActivityTabs';
import { CalendarView } from '../components/CalendarView';
import { NotesList } from '../components/NotesList';
import { RemindersView } from '../components/RemindersView';
import { DailyGoalsView } from '../components/DailyGoalsView';

export function ActivityPage() {
  const { activeTab: tab } = useActivityPage();

  return (
    <div className="space-y-6">
      <header className="space-y-1">
        <h1 className={PAGE_TITLE}>Activity</h1>
        <p className="text-sm text-muted">
          Calendar, notes, reminders, and daily goals — your day at a glance.
        </p>
      </header>

      <ActivityTabs />

      {tab === 'calendar' && <CalendarView />}
      {tab === 'notes' && <NotesList />}
      {tab === 'reminders' && <RemindersView />}
      {tab === 'goals' && <DailyGoalsView />}
    </div>
  );
}
