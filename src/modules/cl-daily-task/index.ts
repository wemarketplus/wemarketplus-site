// CommunityLink Daily Task — the self-assembling morning list.
//
// The guide tells every Sales Marketer to "Check Daily Task (or your Dashboard)
// every morning", but /daily-tasks is HospiceLink-only (it renders the HL
// daily-queue payload: jobs, prospects, referral sources). This module builds the
// CommunityLink equivalent from the three triggers the guide names — a follow-up
// date arriving, a tour today, a lead gone quiet — over cl/leads and cl/tours.
//
// No API slice of its own; see hooks/useClDailyTask for the derivations and the
// sampling caveat they inherit.
export { ClDailyTaskPage } from './pages/ClDailyTaskPage';
export { useClDailyTask } from './hooks/useClDailyTask';
export {
  CL_QUIET_AFTER_DAYS,
  CL_DAILY_TASK_FETCH_LIMIT,
} from './constants/clDailyTaskConstants';
export type {
  ClDailyTaskData,
  ClFollowUpRow,
  ClQuietRow,
} from './hooks/useClDailyTask';
