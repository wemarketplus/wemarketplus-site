// Grant-CRM training providers — full CRUD UI on the shared entity kit (rosters
// remain API-only for now).
export { TrainingProvidersPage } from './pages/TrainingProvidersPage';
export {
  trainingApi,
  useListTrainingProvidersQuery,
  useGetTrainingProviderQuery,
  useGetTrainingProviderStatsQuery,
  useCreateTrainingProviderMutation,
  useUpdateTrainingProviderMutation,
  useDeleteTrainingProviderMutation,
  useListRostersQuery,
  useGetRosterQuery,
  useCreateRosterMutation,
  useImportRostersMutation,
  useUpdateRosterMutation,
  useDeleteRosterMutation,
} from './api/trainingApi';
export {
  trainingProvidersCsvUrl,
  trainingProvidersXlsxUrl,
  rosterExportUrl,
  downloadTrainingExport,
} from './utils/trainingExportUrls';
export type {
  TrainingProviderRecord,
  CreateTrainingProviderRequest,
  RosterRecord,
  CreateRosterRequest,
  ListRostersQuery,
} from './types/trainingTypes';
export {
  TRAINING_PROVIDER_STATUS,
  TRAINING_PROVIDER_STATUS_LABELS,
  COMPLETION_STATUS,
  type TrainingProviderStatus,
  type CompletionStatus,
} from './constants/trainingConstants';
