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
    ...opt('outcome', values.outcome),
    ...opt('notes', values.notes),
  };
}

export function toUpdateTour(
  values: TourFormValues,
  scheduledAtIso: string,
): UpdateClTourRequest {
  return toCreateTour(values, scheduledAtIso);
}

// Seeds the edit form from an existing record.
export function toTourFormValues(r: ClTourRecord): TourFormValues {
  return {
    leadId: r.leadId ?? '',
    scheduledAt: isoToLocalInput(r.scheduledAt),
    status: r.status,
    durationMin: String(r.durationMin ?? 60),
    outcome: r.outcome ?? '',
    notes: r.notes ?? '',
  };
}
