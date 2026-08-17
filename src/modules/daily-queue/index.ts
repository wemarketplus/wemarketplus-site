export { DailyQueuePage } from './pages/DailyQueuePage';
export { ClDailyTasksPage } from './pages/ClDailyTasksPage';
// "My Queue" — the CommunityLink field-ops counterpart, mounted at /my-queue.
// A separate route rather than a branch of DailyTasksRoute: it is a different
// AUDIENCE, not a different product. The field roles are excluded from the sales
// queue by the API itself, so one path serving both would 403 for whoever it was
// not built for.
export { ClFieldQueuePage } from './pages/ClFieldQueuePage';
// The product-aware entry point the router mounts at /daily-tasks.
export { DailyTasksRoute } from './pages/DailyTasksRoute';
export {
  dailyQueueApi,
  useGetDailyQueueQuery,
  useGetClDailyQueueQuery,
  useGetClFieldQueueQuery,
} from './api/dailyQueueApi';
export { useDailyQueue } from './hooks/useDailyQueue';
// The queue's section shell — heading, count and the "nothing due" empty state.
// Exported so the other morning screens (CommunityLink's Daily Task and the
// dashboards' My Queue panel) render a section the same way rather than each
// growing its own idea of what an empty list should look like.
export { QueueSection } from './components/QueueSection';
export type {
  ClDailyQueue,
  ClFieldQueue,
  DailyQueue,
  ReengagementRow,
} from './types/dailyQueueTypes';
