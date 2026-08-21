import { opt, optOrNull } from '@/shared/ui/entity';
import type { TerritoryPriority } from '../constants/territoriesConstants';
import type {
  CreateTerritoryRequest,
  TerritoryRecord,
  UpdateTerritoryRequest,
} from '../types/territoriesTypes';
import type { TerritoryFormValues } from '../schema/territorySchema';

// Splits the comma/whitespace-separated zip text field into a clean string[].
// Returns undefined when empty so the optional DTO field is omitted.
function parseZipCodes(value: string | undefined): string[] | undefined {
  const codes = (value ?? '')
    .split(/[\s,]+/)
    .map((z) => z.trim())
    .filter(Boolean);
  return codes.length ? codes : undefined;
}

// Form values -> POST /territories body. Drops blank optionals so we never send
// empty strings the DTO rejects (assignedTo is IsUUID gated).
export function toCreateTerritory(values: TerritoryFormValues): CreateTerritoryRequest {
  const zipCodes = parseZipCodes(values.zipCodes);
  return {
    name: values.name.trim(),
    ...opt('city', values.city),
    ...opt('state', values.state),
    ...(zipCodes ? { zipCodes } : {}),
    // optOrNull, not opt: an omitted key in a PATCH means "leave unchanged", so
    // `opt` made a territory's owner impossible to remove once set. The column
    // is nullable and the DTO field is @IsOptional, so an explicit null clears
    // it. Same fix as cl-tasks/tasksUtils.ts.
    ...optOrNull('assignedTo', values.assignedTo),
    ...(values.priority ? { priority: values.priority as TerritoryPriority } : {}),
    ...opt('notes', values.notes),
  };
}

// PATCH body is the same shape (backend update whitelist matches create).
export function toUpdateTerritory(values: TerritoryFormValues): UpdateTerritoryRequest {
  return toCreateTerritory(values);
}

// Seeds the edit form from an existing record (nulls -> '', array -> csv text).
export function toTerritoryFormValues(record: TerritoryRecord): TerritoryFormValues {
  return {
    name: record.name,
    city: record.city ?? '',
    state: record.state ?? '',
    zipCodes: (record.zipCodes ?? []).join(', '),
    assignedTo: record.assignedTo ?? '',
    priority: record.priority,
    notes: record.notes ?? '',
  };
}
