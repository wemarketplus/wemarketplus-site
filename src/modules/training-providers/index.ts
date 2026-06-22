// Grant-CRM training providers + rosters — API-only module (no page UI yet).
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
  COMPLETION_STATUS,
  type TrainingProviderStatus,
  type CompletionStatus,
} from './constants/trainingConstants';
