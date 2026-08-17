import {
  CircleUserRound,
  Building2,
  Plug,
  ShieldCheck,
  Phone,
  Sparkles,
  HardDrive,
  MessageCircle,
  DownloadCloud,
  UserCog,
} from 'lucide-react';
import type { ComponentType } from 'react';
import { Product } from '@/shared/types';
import type { SettingsIntegration, SettingsTab } from '../types/settingsTypes';

export const SETTINGS_TABS: readonly SettingsTab[] = [
  'profile',
  'organization',
  'roles',
  'integrations',
  'security',
  'data-export',
];

/**
 * Tabs that only exist on one product's Settings screen. `roles` is
 * CommunityLink-only: its Administrator guide is the one that says "In Settings,
 * look for Manage Roles", whereas a HospiceLink admin is sent to the
 * Roles & permissions page — which still carries the same panel, for both
 * products. Resolved by useSettingsTabs, not read directly by components.
 */
export const SETTINGS_TABS_BY_PRODUCT: Partial<Record<SettingsTab, Product>> = {
  roles: Product.CommunityLink,
};

/** Tabs whose backing endpoints are Admin/Owner-only server-side. */
export const ADMIN_SETTINGS_TABS: readonly SettingsTab[] = ['roles'];

export const SETTINGS_TAB_LABELS: Record<SettingsTab, string> = {
  profile: 'Profile',
  organization: 'Organization',
  roles: 'Manage roles',
  integrations: 'Integrations',
  security: 'Security',
  'data-export': 'Data export',
};

export const SETTINGS_TAB_ICONS: Record<
  SettingsTab,
  ComponentType<{ className?: string }>
> = {
  profile: CircleUserRound,
  organization: Building2,
  roles: UserCog,
  integrations: Plug,
  security: ShieldCheck,
  'data-export': DownloadCloud,
};

// Integration tiles. Only Google Drive has a per-tenant status endpoint
// (GET /drive/status), so it is the sole 'live' tile — its connected state is
// resolved at render time in IntegrationsTab. The rest are 'managed':
// configured server side by an administrator with no per-tenant status route,
// so they are labeled honestly instead of faking a "Connected" badge.
export const DRIVE_INTEGRATION_ID = 'google-drive';

export const INTEGRATIONS: readonly SettingsIntegration[] = [
  {
    id: DRIVE_INTEGRATION_ID,
    name: 'Google Drive',
    description: 'Store and attach referral documents from Google Drive.',
    icon: HardDrive,
    kind: 'live',
  },
  {
    id: 'aircall',
    name: 'Aircall',
    description: 'Phone, text, and email from inside the CRM (Gold tier).',
    icon: Phone,
    kind: 'managed',
  },
  {
    id: 'ai-assistant',
    name: 'AI assistant',
    description: 'Drafts, summaries, and conversion scoring.',
    icon: Sparkles,
    kind: 'managed',
  },
  {
    id: 'secure-messaging',
    name: 'Secure messaging',
    description: 'HIPAA-compliant chat (Gold tier).',
    icon: MessageCircle,
    kind: 'managed',
  },
];

/**
 * Report time zones offered in Organization settings.
 *
 * A curated list of US zones rather than the full IANA database (600+ entries):
 * the product serves US hospice agencies, and a searchable global picker would
 * be a worse experience for a field whose answer is almost always one of these.
 *
 * The BACKEND validates against the runtime's tz database, not this list, so a
 * tenant needing a zone outside it can still be set by support without a
 * frontend release — and this list can grow without a migration.
 */
export const REPORT_TIMEZONE_OPTIONS: ReadonlyArray<{
  value: string;
  label: string;
}> = [
  { value: 'America/New_York', label: 'Eastern (New York)' },
  { value: 'America/Chicago', label: 'Central (Chicago)' },
  { value: 'America/Denver', label: 'Mountain (Denver)' },
  { value: 'America/Phoenix', label: 'Arizona (no DST)' },
  { value: 'America/Los_Angeles', label: 'Pacific (Los Angeles)' },
  { value: 'America/Anchorage', label: 'Alaska (Anchorage)' },
  { value: 'Pacific/Honolulu', label: 'Hawaii (Honolulu)' },
];

/** Matches the backend default on tenants.reportTimezone. */
export const DEFAULT_REPORT_TIMEZONE = 'America/New_York';
