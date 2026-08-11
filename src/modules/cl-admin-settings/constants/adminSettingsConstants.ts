import { AlertChannel } from '../types/adminSettingsApiTypes';

/**
 * Human copy for each alert type.
 *
 * This is a LOOKUP, not the list. The list itself now comes from
 * GET /alert-settings, which scopes it to the products the tenant actually
 * holds — a HospiceLink agency must not be shown CommunityLink's `tour` and
 * `move_in` events, and vice versa. Owning the list here (as this file used to)
 * made that impossible and meant the screen could offer a type the dispatcher
 * would never raise.
 *
 * Covers both products' vocabularies because the screen serves both. An unknown
 * key degrades to a humanised label rather than rendering blank — see
 * alertTypeMeta.
 */
export const ALERT_TYPE_META: Record<
  string,
  { label: string; description: string }
> = {
  // CommunityLink
  paid_referral: { label: 'Paid referral received', description: 'A new paid referral comes in from a placement agency.' },
  tour: { label: 'Tour scheduled', description: 'A prospect tour is booked or rescheduled.' },
  move_in: { label: 'Move-in', description: 'A lead converts to a confirmed move-in.' },
  lost_lead: { label: 'Lost lead', description: 'A lead is marked lost.' },
  organic_lead: { label: 'Organic lead', description: 'A new inbound lead arrives with no referral source.' },
  // HospiceLink
  admission: { label: 'Admission recorded', description: 'A pipeline row reaches the admitted stage.' },
  prospect_lost: { label: 'Pipeline closed as lost', description: 'A pipeline row is closed as lost, with a reason.' },
  referral_received: { label: 'Referral received', description: 'A referral arrives from any origin.' },
  referral_source_cold: { label: 'Referral source went cold', description: 'An account passes the cold threshold with no logged interaction.' },
  // Shared
  failed_payment: { label: 'Failed payment', description: 'A billing charge fails for this tenant.' },
};

/**
 * Copy for an alert type, falling back to a humanised key. A type added on the
 * server ships as a usable row here without a frontend release.
 */
export const alertTypeMeta = (
  key: string,
): { label: string; description: string } =>
  ALERT_TYPE_META[key] ?? {
    label: key.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase()),
    description: 'Configure who is notified when this event occurs.',
  };

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
