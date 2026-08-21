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
