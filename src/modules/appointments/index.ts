export { AppointmentsPage } from './pages/AppointmentsPage';
export { AppointmentsCalendar } from './components/AppointmentsCalendar';
// Record-level scheduling, used from the Prospect and Referral Source screens.
export { ScheduleVisitModal } from './components/ScheduleVisitModal';
// Exported for the nurse's own visit schedule (modules/clinical), which reuses this
// feed and its complete action rather than growing a second "my visits" list.
export { CompleteAppointmentModal } from './components/CompleteAppointmentModal';
export { default as appointmentsReducer } from './store/appointmentsSlice';
export { useAppointmentsCalendar } from './hooks/useAppointmentsCalendar';
export { useAppointmentsMonth } from './hooks/useAppointmentsMonth';
export { AppointmentsMonthGrid } from './components/AppointmentsMonthGrid';
// The shared-calendar palette. Exported so the personal profile picker offers
// exactly the colours the calendar can render — there is one palette, and it
// lives with the surface that draws it.
export {
  CALENDAR_PALETTE,
  calendarColorFor,
  paletteEntryForHex,
} from './utils/calendarColors';
export type {
  CalendarColor,
  CalendarPaletteEntry,
} from './utils/calendarColors';
// The tenant's chosen colours, as a lookup. Exported alongside the palette so
// CommunityLink's calendar colours its team by the same values HospiceLink's does
// — one palette and one source of chosen colours across both products.
export {
  useTenantCalendarColors,
  type CalendarColorMap,
} from './hooks/useTenantCalendarColors';
export { useAppointmentActions } from './hooks/useAppointmentActions';
export {
  appointmentsApi,
  useListAppointmentsQuery,
  useGetCalendarQuery,
  useGetAppointmentQuery,
  useScheduleVisitMutation,
  useCreateAppointmentMutation,
  useUpdateAppointmentMutation,
  useCompleteAppointmentMutation,
  useDeleteAppointmentMutation,
} from './api/appointmentsApi';
