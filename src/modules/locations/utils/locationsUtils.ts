import { opt, optNum } from '@/shared/ui/entity';
import type { LocationStatus } from '../constants/locationsConstants';
import type {
  CreateLocationRequest,
  LocationRecord,
  UpdateLocationRequest,
} from '../types/locationsTypes';
import type { LocationFormValues } from '../schema/locationSchema';

// Form values -> POST /locations body. Drops blank optionals so we never send
// empty strings the DTO rejects (companyId/wibId are IsUUID gated).
export function toCreateLocation(values: LocationFormValues): CreateLocationRequest {
  return {
    locationName: values.locationName.trim(),
    ...(values.status ? { status: values.status as LocationStatus } : {}),
    ...optNum('employeeCount', values.employeeCount),
    ...opt('city', values.city),
    ...opt('county', values.county),
    ...opt('state', values.state),
    ...opt('address', values.address),
    ...opt('companyId', values.companyId),
    ...opt('wibId', values.wibId),
    ...opt('notes', values.notes),
  };
}

// PATCH body — the backend update whitelist is NARROWER than create: it does not
// accept `companyId`/`wibId` (reparenting is not allowed via update). Drop them
// here so an edit never 400s.
export function toUpdateLocation(values: LocationFormValues): UpdateLocationRequest {
  const { companyId: _companyId, wibId: _wibId, ...rest } = toCreateLocation(values);
  return rest;
}

// Seeds the edit form from an existing record (nulls -> '').
export function toLocationFormValues(record: LocationRecord): LocationFormValues {
  return {
    locationName: record.locationName,
    status: record.status,
    employeeCount: record.employeeCount ?? undefined,
    city: record.city ?? '',
    county: record.county ?? '',
    state: record.state ?? '',
    address: record.address ?? '',
    companyId: record.companyId ?? '',
    wibId: record.wibId ?? '',
    notes: record.notes ?? '',
  };
}
