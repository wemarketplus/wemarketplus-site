import { SETTINGS_TABS } from '../constants/settingsConstants';
import type { SettingsTab } from '../types/settingsTypes';

export function isSettingsTab(value: string): value is SettingsTab {
  return (SETTINGS_TABS as readonly string[]).includes(value);
}
