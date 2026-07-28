export const AlertChannel = {
  Email: 'email',
  Sms: 'sms',
  InApp: 'inapp',
  All: 'all',
} as const;
export type AlertChannel = (typeof AlertChannel)[keyof typeof AlertChannel];

// wemarketplus-backend/src/alert-settings — per-tenant alert routing config.
export interface AlertSettingRecord {
  id: string;
  tenantId: string;
  alertType: string;
  enabled: boolean;
  recipientRoles: string[] | null;
  recipientUserIds: string[] | null;
  channel: AlertChannel;
  updatedAt: string;
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
