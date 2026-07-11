import { opt, optNum } from '@/shared/ui/entity';
import type { TelehealthStatus } from '../constants/clinicalStatus';
import type {
  CreateTelehealthSessionRequest,
  TelehealthSessionRecord,
} from '../types/clinicalApiTypes';
import type { TelehealthFormValues } from '../schema/telehealthSchema';

/** Display label for delete-confirm / toasts. */
export function telehealthLabel(session: TelehealthSessionRecord): string {
  return session.patientName || 'telehealth session';
}

// Postgres numeric/decimal columns arrive as STRINGS via TypeORM, so durationMin
// may be a string at runtime. Coerce before any arithmetic/formatting.
export function telehealthDuration(session: TelehealthSessionRecord): number | null {
  if (session.durationMin === null || session.durationMin === undefined) return null;
  const n = Number(session.durationMin);
  return Number.isNaN(n) ? null : n;
}

// A bare `YYYY-MM-DD` from the date input is widened to an ISO datetime so the
// backend's scheduledAt (a Date column) parses it. Already-ISO values pass
// through untouched.
function toIso(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return trimmed;
  return /^\d{4}-\d{2}-\d{2}$/.test(trimmed)
    ? new Date(`${trimmed}T00:00:00`).toISOString()
    : trimmed;
}

// Form values -> POST /telehealth-sessions body. durationMin is parsed from the
// form string and dropped when blank/NaN.
export function toCreateTelehealth(values: TelehealthFormValues): CreateTelehealthSessionRequest {
  const duration = values.durationMin ? Number(values.durationMin) : undefined;
  return {
    patientName: values.patientName.trim(),
    scheduledAt: toIso(values.scheduledAt),
    status: values.status as TelehealthStatus,
    ...opt('providerName', values.providerName),
    ...opt('sessionType', values.sessionType),
    ...optNum('durationMin', duration),
    ...opt('notes', values.notes),
  };
}

export function toUpdateTelehealth(
  values: TelehealthFormValues,
): Partial<CreateTelehealthSessionRequest> {
  return toCreateTelehealth(values);
}

// Seeds the edit form from an existing record (nulls -> '', numeric -> string).
export function toTelehealthFormValues(session: TelehealthSessionRecord): TelehealthFormValues {
  const duration = telehealthDuration(session);
  const scheduled = session.scheduledAt ? session.scheduledAt.slice(0, 10) : '';
  return {
    patientName: session.patientName,
    providerName: session.providerName ?? '',
    sessionType: session.sessionType ?? '',
    scheduledAt: scheduled,
    durationMin: duration === null ? '' : String(duration),
    status: session.status,
    notes: session.notes ?? '',
  };
}
