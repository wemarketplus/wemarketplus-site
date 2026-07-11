import { opt } from '@/shared/ui/entity';
import type { BedUnitStatus } from '../constants/clinicalStatus';
import type { BedUnitRecord, CreateBedUnitRequest } from '../types/clinicalApiTypes';
import type { BedUnitFormValues } from '../schema/bedUnitSchema';

/** Display label for delete-confirm / toasts. */
export function bedUnitLabel(unit: BedUnitRecord): string {
  return unit.facilityName || 'bed unit';
}

// Form values -> POST /bed-units body. Blank optionals are dropped so the DTO's
// forbidNonWhitelisted + no-empty-string rules never fire.
export function toCreateBedUnit(values: BedUnitFormValues): CreateBedUnitRequest {
  return {
    facilityName: values.facilityName.trim(),
    status: values.status as BedUnitStatus,
    ...opt('bedType', values.bedType),
    ...opt('patientName', values.patientName),
    ...opt('notes', values.notes),
  };
}

// PATCH body is the same partial shape; the backend accepts any subset.
export function toUpdateBedUnit(values: BedUnitFormValues): Partial<CreateBedUnitRequest> {
  return toCreateBedUnit(values);
}

// Seeds the edit form from an existing record (nulls -> '').
export function toBedUnitFormValues(unit: BedUnitRecord): BedUnitFormValues {
  return {
    facilityName: unit.facilityName,
    bedType: unit.bedType ?? '',
    status: unit.status,
    patientName: unit.patientName ?? '',
    notes: unit.notes ?? '',
  };
}
