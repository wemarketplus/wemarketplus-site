import type { LatLng, LocationValue } from '../types/geocodingTypes';
import { EMPTY_LOCATION } from '../types/geocodingTypes';

/**
 * Translation between a picker value and the three fields a record stores for
 * it: a label, a latitude and a longitude.
 *
 * Every screen with a location field needs this pair of conversions — mileage's
 * two trip endpoints, an appointment's location, an EVV clock-in and clock-out,
 * an outreach visit — and each one names its columns differently
 * (`fromLocation`/`fromLat`, `location`/`locationLat`, `locationName`/`gpsLat`).
 * The NAMES are the caller's business; the RULE — that a coordinate is only
 * real as a pair, and that a half pair is nothing — is the same everywhere and
 * lives here, so it cannot be got right on three screens and wrong on the
 * fourth.
 */

/** A record's stored label + coordinates as a field value. */
export function toLocationValue(
  label: string | null | undefined,
  lat: number | null | undefined,
  lng: number | null | undefined,
): LocationValue {
  if (!label && lat == null) return EMPTY_LOCATION;
  return {
    label: label ?? '',
    // A half pair is treated as no coordinates rather than as a point: a
    // latitude with no longitude cannot be drawn, and pretending otherwise puts
    // a pin on the prime meridian.
    coords: lat != null && lng != null ? { lat, lng } : null,
  };
}

/** The same value split back into what a request carries. */
export function fromLocationValue(value: LocationValue): {
  label?: string;
  lat?: number;
  lng?: number;
} {
  return {
    // `undefined`, not `''`: the API treats undefined as "not supplied", and an
    // empty string would be a claim that the location is known to be blank.
    label: value.label.trim() || undefined,
    lat: value.coords?.lat,
    lng: value.coords?.lng,
  };
}

/** Whether two values point at the same place — used to skip no-op writes. */
export const sameCoords = (a: LatLng | null, b: LatLng | null): boolean =>
  a === b || (a !== null && b !== null && a.lat === b.lat && a.lng === b.lng);
