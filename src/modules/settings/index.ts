// Public surface of the settings module.
export { SettingsPage } from './pages/SettingsPage';
// The personal (every-role) counterpart to the admin-gated SettingsPage.
export { MyProfilePage } from './pages/MyProfilePage';
export { default as settingsReducer } from './store/settingsSlice';
export { settingsApi } from './api/settingsApi';
