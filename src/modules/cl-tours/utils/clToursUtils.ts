import { toLocationValue, type LocationValue } from '@/modules/geocoding';
import { opt } from '@/shared/ui/entity';
import type {
  ClTourRecord,
  CreateClTourRequest,
  UpdateClTourRequest,
} from '../types/clToursApiTypes';
import type { TourFormValues } from '../schema/clTourSchema';

// datetime-local gives "2026-06-25T14:30" (no zone). The backend wants a full
// ISO timestamp, so interpret it as local time and serialise to ISO.
export function localToIso(local: string): string | null {
  const ms = Date.parse(local);
  return Number.isNaN(ms) ? null : new Date(ms).toISOString();
}

// ISO timestamp -> the value a datetime-local input expects
// ("YYYY-MM-DDTHH:mm" in local time).
export function isoToLocalInput(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const tz = d.getTimezoneOffset() * 60_000;
  return new Date(d.getTime() - tz).toISOString().slice(0, 16);
}

/** Human date + time for a tour row. */
export function tourWhen(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

/**
 * A stored coordinate as a number, or undefined.
 *
 * `cl_tours.fromLat` is `numeric(10,7)` and the CL controllers return the entity
 * unmapped, so the pg driver's STRING ("32.7766642") is what actually arrives —
 * see ClTourRecord. Number() here is the single place that is dealt with; a map
 * marker handed a string silently renders nothing.
 */
const coord = (value: number | string | null): number | undefined => {
  if (value === null || value === '') return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
};

/**
 * One endpoint of a tour as the picker's value — for the form and for the table's
 * From/To columns, which must agree about what "no location" looks like.
 */
export function tourEndpoint(
  tour: ClTourRecord,
  side: 'from' | 'to',
): LocationValue {
  return side === 'from'
    ? toLocationValue(tour.fromLocation, coord(tour.fromLat), coord(tour.fromLng))
    : toLocationValue(tour.toLocation, coord(tour.toLat), coord(tour.toLng));
}

/**
 * The three request keys for one endpoint on a CREATE: blanks are OMITTED, since
 * a new tour has nothing to clear and the API treats an absent key as "not
 * supplied".
 */
function endpointCreate(
  side: 'from' | 'to',
  label: string | undefined,
  lat: number | undefined,
  lng: number | undefined,
): Partial<CreateClTourRequest> {
  const paired = lat !== undefined && lng !== undefined;
  return {
    ...opt(`${side}Location`, label),
    ...(paired ? { [`${side}Lat`]: lat, [`${side}Lng`]: lng } : {}),
  };
}

/**
 * The same three keys on an UPDATE, where a blank must be an explicit `null`.
 *
 * An omitted key means "leave unchanged" (TypeORM's `merge` skips undefined), so
 * omitting is how clearing the field in the edit form would silently put the old
 * place back — the row keeping coordinates whose label the user just deleted.
 * Every key is therefore always sent, and the server's clearable-paired
 * validators accept the null pair.
 *
 * The coordinates are nulled TOGETHER with each other, and also whenever the pin
 * is gone: a lone `fromLat` is a 400 by design.
 */
function endpointPatch(
  side: 'from' | 'to',
  label: string | undefined,
  lat: number | undefined,
  lng: number | undefined,
): Partial<CreateClTourRequest> {
  const trimmed = label?.trim();
  const paired = lat !== undefined && lng !== undefined;
  return {
    [`${side}Location`]: trimmed ? trimmed : null,
    [`${side}Lat`]: paired ? lat : null,
    [`${side}Lng`]: paired ? lng : null,
  };
}

// Form values -> POST /cl/tours body. scheduledAt is validated non-null upstream.
export function toCreateTour(
  values: TourFormValues,
  scheduledAtIso: string,
): CreateClTourRequest {
  return {
    scheduledAt: scheduledAtIso,
    status: values.status,
    durationMin: Number(values.durationMin),
    ...(values.leadId ? { leadId: values.leadId } : {}),
    ...(values.guideUserId ? { guideUserId: values.guideUserId } : {}),
    ...opt('outcome', values.outcome),
    ...opt('notes', values.notes),
    ...endpointCreate('from', values.fromLocation, values.fromLat, values.fromLng),
    ...endpointCreate('to', values.toLocation, values.toLat, values.toLng),
  };
}

/**
 * Form values -> PATCH /cl/tours/:id body.
 *
 * Identical to the create body except for the two endpoints, which are sent as
 * explicit nulls when blank so that clearing a location on the edit form actually
 * takes. (The other optionals keep the module's existing omit-when-blank
 * behaviour — changing those is a separate decision about every CL form.)
 */
export function toUpdateTour(
  values: TourFormValues,
  scheduledAtIso: string,
): UpdateClTourRequest {
  return {
    ...toCreateTour(values, scheduledAtIso),
    ...endpointPatch('from', values.fromLocation, values.fromLat, values.fromLng),
    ...endpointPatch('to', values.toLocation, values.toLat, values.toLng),
  };
}

// Seeds the edit form from an existing record.
export function toTourFormValues(r: ClTourRecord): TourFormValues {
  return {
    leadId: r.leadId ?? '',
    guideUserId: r.guideUserId ?? '',
    scheduledAt: isoToLocalInput(r.scheduledAt),
    status: r.status,
    durationMin: String(r.durationMin ?? 60),
    fromLocation: r.fromLocation ?? '',
    fromLat: coord(r.fromLat),
    fromLng: coord(r.fromLng),
    toLocation: r.toLocation ?? '',
    toLat: coord(r.toLat),
    toLng: coord(r.toLng),
    outcome: r.outcome ?? '',
    notes: r.notes ?? '',
  };
}
