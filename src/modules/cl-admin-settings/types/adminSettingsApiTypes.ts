export const AlertChannel = {
  Email: 'email',
  Sms: 'sms',
  InApp: 'inapp',
  All: 'all',
} as const;
export type AlertChannel = (typeof AlertChannel)[keyof typeof AlertChannel];

// wemarketplus-backend/src/alert-settings — per-tenant alert routing config.
export interface AlertSettingRecord {
  /** Null for an alert type that has never been configured. */
  id: string | null;
  tenantId: string | null;
  alertType: string;
  enabled: boolean;
  recipientRoles: string[] | null;
  recipientUserIds: string[] | null;
  channel: AlertChannel;
  updatedAt: string | null;
  /**
   * False when the row is a server-supplied default rather than a saved
   * setting. Distinguishes "nobody has set this up" from "an admin deliberately
   * turned it off", which look identical otherwise.
   */
  configured: boolean;
}

/**
 * Whether a delivery channel can actually deliver in this deployment
 * (GET /alert-settings/channels).
 *
 * The platform ships no SMS provider, so SMS reports available: false. The UI
 * disables it rather than letting an office manager select a channel that would
 * silently drop every message.
 */
export interface AlertChannelAvailability {
  channel: AlertChannel;
  available: boolean;
  reason: string | null;
}

export interface UpsertAlertSettingRequest {
  alertType: string;
  enabled?: boolean;
  recipientRoles?: string[];
  channel?: AlertChannel;
}

// wemarketplus-backend/src/mileage/financial-settings.controller.ts — per-tenant
// key/value financial config (mileage_rate, gift_gratuity_limit).
export interface FinancialSettingRecord {
  settingKey: string;
  settingValue: string;
}

export interface UpsertFinancialSettingRequest {
  settingKey: string;
  settingValue: string;
}
