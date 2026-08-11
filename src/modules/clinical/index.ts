export { ClinicalPage } from './pages/ClinicalPage';
export { FamilyCommunicationPage } from './pages/FamilyCommunicationPage';
export { default as clinicalReducer } from './store/clinicalSlice';
export {
  clinicalApi,
  useListEvvLogsQuery,
  useClockInMutation,
  useClockOutMutation,
  useListTelehealthQuery,
  useCreateTelehealthMutation,
  useUpdateTelehealthMutation,
  useDeleteTelehealthMutation,
  useListBedUnitsQuery,
  useCreateBedUnitMutation,
  useUpdateBedUnitMutation,
  useDeleteBedUnitMutation,
  useListGiftsQuery,
  useCreateGiftMutation,
  useGetAlertSettingsQuery,
  useUpsertAlertSettingMutation,
} from './api/clinicalApi';
