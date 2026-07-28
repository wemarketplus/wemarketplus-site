export { AppointmentsPage } from './pages/AppointmentsPage';
export { AppointmentsCalendar } from './components/AppointmentsCalendar';
export { default as appointmentsReducer } from './store/appointmentsSlice';
export { useAppointmentsCalendar } from './hooks/useAppointmentsCalendar';
export { useAppointmentActions } from './hooks/useAppointmentActions';
export {
  appointmentsApi,
  useListAppointmentsQuery,
  useGetCalendarQuery,
  useGetAppointmentQuery,
  useCreateAppointmentMutation,
  useUpdateAppointmentMutation,
  useCompleteAppointmentMutation,
  useDeleteAppointmentMutation,
} from './api/appointmentsApi';
