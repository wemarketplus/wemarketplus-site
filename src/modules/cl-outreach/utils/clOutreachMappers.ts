import { opt } from '@/shared/ui/entity';
import type { GPSCheckIn } from '@/shared/types';
import type {
  ClOutreachVisitRecord,
  CreateClOutreachVisitRequest,
} from '../types/clOutreachApiTypes';
import type { VisitFormValues } from '../schema/clOutreachSchema';

// Form values -> POST /cl/outreach-visits body. Drops blank optionals; parses
// miles to a number.
export function toCreateVisit(values: VisitFormValues): CreateClOutreachVisitRequest {
  return {
    visitDate: values.visitDate,
    ...opt('contactName', values.contactName),
    ...opt('locationName', values.locationName),
    ...opt('visitType', values.visitType),
    ...(values.miles?.trim() ? { miles: Number(values.miles) } : {}),
    // Both or neither: a latitude on its own is not a location, and the check-in
    // list renders the pair as one "lat, lng" line — half of which would read as a
    // corrupt fix rather than an absent one.
    ...(values.gpsLat?.trim() && values.gpsLng?.trim()
      ? { gpsLat: Number(values.gpsLat), gpsLng: Number(values.gpsLng) }
      : {}),
    ...opt('notes', values.notes),
  };
}

export function toUpdateVisit(
  values: VisitFormValues,
): Partial<CreateClOutreachVisitRequest> {
  return toCreateVisit(values);
}

export function toVisitFormValues(v: ClOutreachVisitRecord): VisitFormValues {
  return {
    visitDate: v.visitDate,
    contactName: v.contactName ?? '',
    locationName: v.locationName ?? '',
    visitType: v.visitType ?? 'in_person',
    miles: v.miles != null ? String(v.miles) : '',
    gpsLat: v.gpsLat != null ? String(v.gpsLat) : '',
    gpsLng: v.gpsLng != null ? String(v.gpsLng) : '',
    notes: v.notes ?? '',
  };
}

// Pure mapper — kept in utils/ so the hook stays orchestration-only.
//
// `toMileage` used to sit alongside this, projecting the same visit row into a
// MileageEntry for a third "Mileage" lens. Mileage is now the shared
// `mileage_logs` screen, which is the only one carrying from/to, purpose, the
// reimbursement rate and receipts, so that projection had nowhere left to go.
export function toCheckIn(v: ClOutreachVisitRecord): GPSCheckIn {
  const gps = v.gpsLat != null && v.gpsLng != null ? `${v.gpsLat},${v.gpsLng}` : '';
  return {
    id: v.id,
    organization: v.locationName ?? '',
    contactName: v.contactName ?? '',
    gpsLocation: gps,
    visitType: v.visitType ?? '',
    visitDate: v.visitDate,
  };
}

