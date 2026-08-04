import { opt, optNum } from '@/shared/ui/entity';
import { isoToLocalInput, localInputToIso } from '@/shared/utils/dateFormatter';
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

// Form values -> POST /telehealth-sessions body. scheduledAt arrives from a
// datetime-local input as a zoneless local wall clock, so it is interpreted in
// the user's zone and sent as a full ISO instant — the column is a timestamptz
// and carries a real time of day, not just a date. durationMin is already a
// number (number input) and is dropped when blank/NaN.
export function toCreateTelehealth(values: TelehealthFormValues): CreateTelehealthSessionRequest {
  return {
    patientName: values.patientName.trim(),
    scheduledAt: localInputToIso(values.scheduledAt),
    status: values.status as TelehealthStatus,
    ...opt('providerName', values.providerName),
    ...opt('sessionType', values.sessionType),
    ...optNum('durationMin', values.durationMin),
    ...opt('notes', values.notes),
  };
}

export function toUpdateTelehealth(
  values: TelehealthFormValues,
): Partial<CreateTelehealthSessionRequest> {
  return toCreateTelehealth(values);
}

// Seeds the edit form from an existing record (nulls -> '' / undefined). The
// stored instant is rendered in the user's local zone; slicing the ISO string
// would show UTC wall clock and drop the time of day entirely.
export function toTelehealthFormValues(session: TelehealthSessionRecord): TelehealthFormValues {
  const duration = telehealthDuration(session);
  return {
    patientName: session.patientName,
    providerName: session.providerName ?? '',
    sessionType: session.sessionType ?? '',
    scheduledAt: session.scheduledAt ? isoToLocalInput(session.scheduledAt) : '',
    durationMin: duration ?? undefined,
    status: session.status,
    notes: session.notes ?? '',
  };
}
