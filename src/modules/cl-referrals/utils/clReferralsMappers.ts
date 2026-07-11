import { opt } from '@/shared/ui/entity';
import type {
  ClReferralSourceRecord,
  CreateClReferralSourceRequest,
} from '../types/clReferralsApiTypes';
import type { ReferralFormValues } from '../schema/clReferralSchema';

// Form values -> POST /cl/referral-sources body. Drops blank optionals so the
// DTO's IsEmail rule never sees an empty string.
export function toCreateReferral(values: ReferralFormValues): CreateClReferralSourceRequest {
  return {
    name: values.name.trim(),
    ...opt('organization', values.organization),
    ...opt('type', values.type),
    ...opt('phone', values.phone),
    ...opt('email', values.email),
    ...opt('address', values.address),
    ...opt('notes', values.notes),
  };
}

// PATCH body is the same partial shape; the backend accepts any subset.
export function toUpdateReferral(
  values: ReferralFormValues,
): Partial<CreateClReferralSourceRequest> {
  return toCreateReferral(values);
}

// Seeds the edit form from an existing record (nulls -> '').
export function toReferralFormValues(r: ClReferralSourceRecord): ReferralFormValues {
  return {
    name: r.name,
    organization: r.organization ?? '',
    type: (r.type ?? 'physician') as ReferralFormValues['type'],
    phone: r.phone ?? '',
    email: r.email ?? '',
    address: r.address ?? '',
    notes: r.notes ?? '',
  };
}
