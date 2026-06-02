import {
  CircleUserRound,
  Building2,
  Plug,
  ShieldCheck,
  Phone,
  Sparkles,
  Database,
  MessageCircle,
} from 'lucide-react';
import type { ComponentType } from 'react';
import type { SettingsIntegration, SettingsTab } from '../types/settingsTypes';
import type { OrganizationFormValues } from '../schema/organizationSchema';

export const SETTINGS_TABS: readonly SettingsTab[] = [
  'profile',
  'organization',
  'integrations',
  'security',
];

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

// Static integration tiles — mirrors the site's settings page. Each "Connect"
// button is wired with a TODO toast until the backend exposes OAuth flows.
export const INTEGRATIONS: readonly SettingsIntegration[] = [
  {
    id: 'aircall',
    name: 'Aircall',
    description: 'Phone, text, and email from inside the CRM (Gold tier).',
    icon: Phone,
    status: 'available',
  },
  {
    id: 'openai',
    name: 'AI assistant',
    description: 'Drafts, summaries, and conversion scoring.',
    icon: Sparkles,
    status: 'connected',
  },
  {
    id: 'csv-import',
    name: 'Data import',
    description: 'Bulk upload referrals and prospects from CSV/Excel.',
    icon: Database,
    status: 'available',
  },
  {
    id: 'secure-messaging',
    name: 'Secure messaging',
    description: 'HIPAA-compliant chat (Gold tier).',
    icon: MessageCircle,
    status: 'available',
  },
];

// TODO(backend): wire to /organizations when it ships. Today the Organization
// tab validates locally and toasts on submit so the screen is interactive.
export const PLACEHOLDER_ORG: OrganizationFormValues = {
  name: 'Bay Area Hospice Group',
  city: 'San Francisco',
  state: 'CA',
  phone: '(415) 555-2200',
};
