// CommunityLink shared team calendar.
//
// The guide gives this screen its own section ("Your Shared Team Calendar") with a
// My Calendar / All Users dropdown, per-person colours, and direct scheduling of
// tours, facility visits and physician lunches. CommunityLink had no calendar
// route at all — /appointments is HospiceLink-scoped and every appointment there
// requires a `jobId` — so this module builds one over cl/tours and
// cl/outreach-visits.
//
// No API slice of its own: it reads and writes the tour and outreach endpoints
// those modules already own, so a tour booked here is the same record the Tour
// Scheduler lists.
export { ClCalendarPage } from './pages/ClCalendarPage';
export { useClCalendar } from './hooks/useClCalendar';
export { useClScheduleEvent } from './hooks/useClScheduleEvent';
export {
  buildClMonthGrid,
  clLocalDateKey,
  clMonthLabel,
  clShortTime,
  tourToEvent,
  visitToEvent,
} from './utils/clCalendarUtils';
export {
  CL_CALENDAR_FETCH_LIMIT,
  CL_EVENT_KIND_LABELS,
  CL_SCHEDULE_CHOICES,
} from './constants/clCalendarConstants';
export {
  ClCalendarEventKind,
  type ClCalendarCell,
  type ClCalendarEvent,
  type ClCalendarScope,
} from './types/clCalendarTypes';
