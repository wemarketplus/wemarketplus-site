import { ACTIONABLE_LEAD_STATUSES } from '../constants/leadsConstants';
import type { LeadRecord } from '../types/leadsTypes';

/** A lead is actionable until it is converted or disqualified. */
export function isActionable(lead: LeadRecord): boolean {
  return ACTIONABLE_LEAD_STATUSES.includes(lead.status);
}

/** Display label for who/where the referral came from. */
export function referralOrigin(lead: LeadRecord): string {
  const parts = [lead.referringPerson, lead.referringOrg].filter(Boolean);
  return parts.length > 0 ? parts.join(' · ') : '—';
}

/** Strips empty-string form fields so they are not sent as blank values. */
export function compactPayload<T extends Record<string, unknown>>(
  values: T,
): Partial<T> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== null && value !== '') {
      out[key] = value;
    }
  }
  return out as Partial<T>;
}
