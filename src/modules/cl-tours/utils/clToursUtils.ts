import type { Tour } from '@/shared/types';
import type { ClTourRecord } from '../types/clToursApiTypes';

export function sortByDate(tours: readonly Tour[]): Tour[] {
  return [...tours].sort(
    (a, b) => new Date(a.tourDate).getTime() - new Date(b.tourDate).getTime(),
  );
}

// Backend cl/tours keys a tour by leadId (no embedded name) and stores a single
// scheduledAt timestamp; split it into the date/time the UI renders.
export function mapClTour(r: ClTourRecord): Tour {
  const d = new Date(r.scheduledAt);
  const tourDate = r.scheduledAt.slice(0, 10);
  const tourTime = Number.isNaN(d.getTime())
    ? ''
    : d.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' });
  return {
    id: r.id,
    prospectName: r.leadId ?? 'Lead',
    tourDate,
    tourTime,
    tourType: 'in_person',
    notes: r.outcome ?? r.notes ?? undefined,
  };
}
