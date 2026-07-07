import { useLocation, useNavigate } from 'react-router-dom';
import type { ActivityUiState } from '../types/activityTypes';

type Tab = ActivityUiState['activeTab'];

const PATH_BY_TAB: Record<Tab, string> = {
  calendar: '/activity/calendar',
  notes: '/activity/notes',
  reminders: '/activity/reminders',
  goals: '/activity/goals',
};

const TABS: readonly Tab[] = ['calendar', 'notes', 'reminders', 'goals'];

// Each activity tab is its own route (/activity/calendar, /notes, /reminders,
// /goals), so the active tab is derived from the URL and switching navigates —
// each sidebar link opens its own tab instead of all landing on Calendar.
export function useActivityTabs() {
  const { pathname } = useLocation();
  const navigate = useNavigate();

  const segment = pathname.split('/').pop() as Tab | undefined;
  const activeTab: Tab = segment && TABS.includes(segment) ? segment : 'calendar';

  const setTab = (tab: Tab) => navigate(PATH_BY_TAB[tab]);

  return { activeTab, setTab };
}
