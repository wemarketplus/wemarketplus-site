export { AlertSettingsPage } from './pages/AlertSettingsPage';
export { FinancialSettingsPage } from './pages/FinancialSettingsPage';
export {
  adminSettingsApi,
  useListAlertSettingsQuery,
  useUpsertAlertSettingMutation,
  useListFinancialSettingsQuery,
  useUpsertFinancialSettingMutation,
} from './api/adminSettingsApi';

// Shared with HospiceLink's Notifications > Alerts tab — see the component.
export { AlertRoutingPanel } from './components/AlertRoutingPanel';
