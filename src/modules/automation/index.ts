export { AutomationPage } from './pages/AutomationPage';
export {
  automationApi,
  useListFollowUpsQuery,
  useCreateFollowUpMutation,
  useCancelFollowUpMutation,
} from './api/automationApi';
export { useAutomation } from './hooks/useAutomation';
export { FollowUpFormModal } from './components/FollowUpFormModal';
export { followUpSchema, type FollowUpFormValues } from './schema/followUpSchema';
export type {
  FollowUpAutomationRecord,
  CreateFollowUpRequest,
  ListFollowUpsQuery,
} from './types/automationTypes';
