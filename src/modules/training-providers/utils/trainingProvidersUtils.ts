import { opt } from '@/shared/ui/entity';
import type { TrainingProviderStatus } from '../constants/trainingConstants';
import type {
  CreateTrainingProviderRequest,
  TrainingProviderRecord,
} from '../types/trainingTypes';
import type { TrainingProviderFormValues } from '../schema/trainingProviderSchema';

// Form values -> POST /training-providers body. Drops blank optionals so we never
// send empty strings the DTO rejects (contactEmail is IsEmail gated).
export function toCreateTrainingProvider(
  values: TrainingProviderFormValues,
): CreateTrainingProviderRequest {
  return {
    name: values.name.trim(),
    ...opt('providerType', values.providerType),
    ...opt('website', values.website),
    ...opt('contactEmail', values.contactEmail),
    ...opt('contactPhone', values.contactPhone),
    ...opt('programs', values.programs),
    ...opt('state', values.state),
    ...(values.status ? { status: values.status as TrainingProviderStatus } : {}),
    ...opt('notes', values.notes),
  };
}

// PATCH body is the same shape (backend update whitelist matches create).
export function toUpdateTrainingProvider(
  values: TrainingProviderFormValues,
): Partial<CreateTrainingProviderRequest> {
  return toCreateTrainingProvider(values);
}

// Seeds the edit form from an existing record (nulls -> '').
export function toTrainingProviderFormValues(
  record: TrainingProviderRecord,
): TrainingProviderFormValues {
  return {
    name: record.name,
    providerType: record.providerType ?? '',
    website: record.website ?? '',
    contactEmail: record.contactEmail ?? '',
    contactPhone: record.contactPhone ?? '',
    programs: record.programs ?? '',
    state: record.state ?? '',
    status: record.status,
    notes: record.notes ?? '',
  };
}
