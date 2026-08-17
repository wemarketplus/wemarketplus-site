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
export type {
  ClDailyQueue,
  ClFieldQueue,
  DailyQueue,
  ReengagementRow,
} from './types/dailyQueueTypes';
