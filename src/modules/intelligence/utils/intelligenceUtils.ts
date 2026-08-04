import {
  LEAD_ORIGIN_LABELS,
  LOST_REASON_LABELS,
} from '../constants/intelligenceConstants';

/**
 * Money, whole dollars. These are account-level totals so cents are noise — but the
 * value is never rounded before it reaches this function, so a column's displayed
 * total always matches the total the API computed.
 */
export function formatMoney(value: number): string {
  return value.toLocaleString('en-US', {
    style: 'currency',
    currency: 'USD',
    maximumFractionDigits: 0,
  });
}

/**
 * A 0-1 rate as a percentage. `null` means "not applicable" (no denominator) and
 * renders as an em dash rather than 0% — an account with no prospects has no
 * conversion rate, which is a different statement from a conversion rate of zero.
 */
export function formatRate(rate: number | null): string {
  return rate === null ? '—' : `${(rate * 100).toFixed(0)}%`;
}

/** A per-unit money figure, or an em dash when the denominator was zero. */
export function formatMoneyPerUnit(value: number | null): string {
  return value === null ? '—' : formatMoney(value);
}

/** A count, or an em dash when not applicable. */
export function formatCount(value: number | null): string {
  return value === null ? '—' : value.toLocaleString('en-US');
}

export function formatLeadOrigin(sourceType: string): string {
  return LEAD_ORIGIN_LABELS[sourceType] ?? sourceType;
}

export function formatLostReason(reason: string): string {
  return LOST_REASON_LABELS[reason] ?? reason;
}

/** `2026-08` -> `Aug 2026`, for the monthly revenue trend. */
export function formatMonth(month: string): string {
  const [year, m] = month.split('-');
  const index = Number(m) - 1;
  const names = [
    'Jan',
    'Feb',
    'Mar',
    'Apr',
    'May',
    'Jun',
    'Jul',
    'Aug',
    'Sep',
    'Oct',
    'Nov',
    'Dec',
  ];
  return names[index] ? `${names[index]} ${year}` : month;
}

/**
 * Share of billed revenue that carries a referral source, 0-1. Returns null when
 * nothing was billed at all — with no revenue there is no attribution rate to
 * report, and showing 0% would read as a failure to attribute.
 */
export function attributionRate(
  attributed: number,
  total: number,
): number | null {
  return total > 0 ? attributed / total : null;
}
