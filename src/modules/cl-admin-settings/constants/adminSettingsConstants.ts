import { AlertChannel } from '../types/adminSettingsApiTypes';

// Mirrors the backend's SEEDED_ALERT_TYPES (alert-settings.constants.ts) —
// the list is not auto-seeded server-side, so the frontend owns which alert
// types are configurable and falls back to sane defaults for any type that
// has no saved row yet.
export const ALERT_TYPES: ReadonlyArray<{ key: string; label: string; description: string }> = [
  { key: 'paid_referral', label: 'Paid referral received', description: 'A new paid referral comes in from a placement agency.' },
  { key: 'tour', label: 'Tour scheduled', description: 'A prospect tour is booked or rescheduled.' },
  { key: 'move_in', label: 'Move-in', description: 'A lead converts to a confirmed move-in.' },
  { key: 'lost_lead', label: 'Lost lead', description: 'A lead is marked lost.' },
  { key: 'organic_lead', label: 'Organic lead', description: 'A new inbound lead arrives with no referral source.' },
  { key: 'failed_payment', label: 'Failed payment', description: 'A billing charge fails for this tenant.' },
];

export const ALERT_CHANNEL_OPTIONS: ReadonlyArray<{ value: AlertChannel; label: string }> = [
  { value: AlertChannel.Email, label: 'Email' },
  { value: AlertChannel.Sms, label: 'SMS' },
  { value: AlertChannel.InApp, label: 'In-app' },
  { value: AlertChannel.All, label: 'All channels' },
];

export const FINANCIAL_SETTING_DEFS: ReadonlyArray<{
  key: string;
  label: string;
  hint: string;
  suffix: string;
  defaultValue: string;
}> = [
  { key: 'mileage_rate', label: 'Mileage reimbursement rate', hint: 'Per mile (IRS 2026 standard rate).', suffix: '/ mile', defaultValue: '0.67' },
  { key: 'gift_gratuity_limit', label: 'Gift & gratuity limit', hint: 'Max value per visit before a compliance flag.', suffix: '/ visit', defaultValue: '15.00' },
  { key: 'parking_max', label: 'Parking expense max', hint: 'Per-day maximum reimbursable parking expense.', suffix: '/ day', defaultValue: '20.00' },
  { key: 'meal_max', label: 'Meal expense max', hint: 'Per-person maximum when meals are allowed.', suffix: '', defaultValue: '25.00' },
  { key: 'referral_fee_default', label: 'Default referral fee', hint: 'Auto-fills when adding a new paid referral.', suffix: '', defaultValue: '2000.00' },
];
