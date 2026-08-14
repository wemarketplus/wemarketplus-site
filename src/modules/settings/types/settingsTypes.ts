import type { ComponentType } from 'react';

// Settings UI state. Server-shaped DTOs (org profile, integration tokens)
// live alongside their owning modules — settings/ only stores the picker
// state for which tab is currently in view.

export type SettingsTab =
  | 'profile'
  | 'organization'
  | 'roles'
  | 'integrations'
  | 'security'
  | 'data-export';

export interface SettingsUiState {
  activeTab: SettingsTab;
}

// How an integration's status is sourced:
//   - 'live'   -> a real backend status endpoint drives connected/not-connected
//                 (only Google Drive today, via GET /drive/status).
//   - 'managed' -> configured server side by an administrator; there is no
//                  per-tenant status endpoint, so we label it honestly rather
//                  than claim a live "Connected" state.
export type IntegrationKind = 'live' | 'managed';

export interface SettingsIntegration {
  id: string;
  name: string;
  description: string;
  icon: ComponentType<{ className?: string }>;
  kind: IntegrationKind;
}
