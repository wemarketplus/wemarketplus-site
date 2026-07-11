import { useActivityTabs } from './useActivityTabs';

// The active tab is derived from the URL (each activity tab is its own route),
// so ActivityPage and ActivityTabs stay in sync. Previously this read a Redux
// flag that the URL-based tabs never updated, so the rendered view was stuck on
// Calendar regardless of which tab was selected.
export function useActivityPage() {
  const { activeTab } = useActivityTabs();
  return { activeTab };
}
