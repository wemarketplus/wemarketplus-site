import { CircleUserRound, Building2, Plug, ShieldCheck } from 'lucide-react';
import type { ComponentType } from 'react';
import type { SettingsTab } from '../types/settingsTypes';

export const SETTINGS_TAB_LABELS: Record<SettingsTab, string> = {
  profile: 'Profile',
  organization: 'Organization',
  integrations: 'Integrations',
  security: 'Security',
};

export const SETTINGS_TAB_ICONS: Record<
  SettingsTab,
  ComponentType<{ className?: string }>
> = {
  profile: CircleUserRound,
  organization: Building2,
  integrations: Plug,
  security: ShieldCheck,
};
