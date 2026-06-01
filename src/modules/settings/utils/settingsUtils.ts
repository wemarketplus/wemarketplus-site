import { SETTINGS_TABS, type SettingsTab } from '../types/settingsTypes';

export function isSettingsTab(value: string): value is SettingsTab {
  return (SETTINGS_TABS as readonly string[]).includes(value);
}
