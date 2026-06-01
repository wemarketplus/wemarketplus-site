// Settings UI state. Server-shaped DTOs (org profile, integration tokens)
// live alongside their owning modules — settings/ only stores the picker
// state for which tab is currently in view.

export const SETTINGS_TABS = [
  'profile',
  'organization',
  'integrations',
  'security',
] as const;
export type SettingsTab = (typeof SETTINGS_TABS)[number];

export interface SettingsUiState {
  activeTab: SettingsTab;
}
