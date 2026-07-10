import type { GPSCheckIn, MileageEntry } from '@/shared/types';
import type { ClOutreachVisitRecord } from '../types/clOutreachApiTypes';

// A single backend outreach visit feeds both the GPS check-in list and the
// mileage log in the UI. Pure mappers — kept in utils/ so the hook stays
// orchestration-only.
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

export function toMileage(v: ClOutreachVisitRecord): MileageEntry {
  return {
    id: v.id,
    distanceMiles: v.miles ?? 0,
    date: v.visitDate,
    purpose: v.visitType ?? v.locationName ?? 'Outreach visit',
    notes: v.notes ?? undefined,
  };
}
