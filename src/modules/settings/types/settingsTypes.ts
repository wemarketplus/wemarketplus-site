import type { ComponentType } from 'react';

// Settings UI state. Server-shaped DTOs (org profile, integration tokens)
// live alongside their owning modules — settings/ only stores the picker
// state for which tab is currently in view.

export type SettingsTab = 'profile' | 'organization' | 'integrations' | 'security';

export interface SettingsUiState {
  activeTab: SettingsTab;
}

export interface SettingsIntegration {
  id: string;
  name: string;
  description: string;
  icon: ComponentType<{ className?: string }>;
  status: 'available' | 'connected';
}
