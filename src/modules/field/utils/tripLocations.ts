import {
  formatCoords,
  fromLocationValue,
  type LocationValue,
} from '@/modules/geocoding';
import type {
  CreateMileageLogRequest,
  MileageLogRecord,
} from '../types/fieldTypes';

/**
 * Translation between a trip row and the location picker's value shape.
 *
 * One file because these three all encode the same rule — a trip endpoint is a
 * LABEL plus an optional PAIR of coordinates — and a rule split across a form, a
 * table cell and a request builder is a rule that gets half-updated.
 */

/**
 * One picked endpoint as the fields the create request carries for it.
 *
 * Absent values stay `undefined` rather than becoming `null` or `''`: the
 * server's DTO treats undefined as "not supplied" and validates coordinates in
 * PAIRS, so an endpoint with a name but no pin sends a label alone, and a
 * cleared field sends nothing at all — neither can produce the half-pair that
 * would 400.
 */
export function endpointFields(
  side: 'from' | 'to',
  value: LocationValue,
): Partial<CreateMileageLogRequest> {
  const { label, lat, lng } = fromLocationValue(value);
  return side === 'from'
    ? { fromLocation: label, fromLat: lat, fromLng: lng }
    : { toLocation: label, toLat: lat, toLng: lng };
}

/** True when EITHER endpoint of the trip was picked on a map rather than typed. */
export const hasCoordinates = (log: MileageLogRecord): boolean =>
  (log.fromLat !== null && log.fromLng !== null) ||
  (log.toLat !== null && log.toLng !== null);

/** Both endpoints' fixes, for the route cell's tooltip. */
export function routeCoordinates(log: MileageLogRecord): string {
  const parts: string[] = [];
  if (log.fromLat !== null && log.fromLng !== null) {
    parts.push(`From ${formatCoords({ lat: log.fromLat, lng: log.fromLng })}`);
  }
  if (log.toLat !== null && log.toLng !== null) {
    parts.push(`To ${formatCoords({ lat: log.toLat, lng: log.toLng })}`);
  }
  return parts.join(' · ');
}

/**
 * The human route for a trip, or null when neither endpoint is recorded.
 *
 * WHY THIS IS NOT `${from ?? '—'} → ${to ?? '—'}`. That template — which the
 * route column and the attach-receipt dialog title each spelled out for
 * themselves — renders "— → —" for a trip logged with neither endpoint, and
 * "— → Baylor Medical" for one logged with only a destination. An em dash is
 * this app's "no value" marker everywhere else (see the Purpose and
 * Reimbursement columns), so an arrow BETWEEN two of them reads as a route
 * between two unknown places rather than as an absent route, and QA read the
 * pair as stray symbols. Punctuation cannot say "nothing here" twice and stay
 * legible.
 *
 * So the arrow appears only when there are genuinely two endpoints to join.
 * One-sided trips name the side they have — a trip TO somewhere is a real,
 * common thing to log — and a trip with neither returns null for the caller to
 * render with its own empty marker.
 */
export function routeLabel(log: {
  fromLocation: string | null;
  toLocation: string | null;
}): string | null {
  const from = log.fromLocation?.trim() || null;
  const to = log.toLocation?.trim() || null;
  if (from && to) return `${from} → ${to}`;
  if (from) return `From ${from}`;
  if (to) return `To ${to}`;
  return null;
}
