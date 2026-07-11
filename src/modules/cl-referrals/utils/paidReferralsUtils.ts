import { opt } from '@/shared/ui/entity';
import type {
  ClPaidReferralRecord,
  CreateClPaidReferralRequest,
} from '../types/clReferralsApiTypes';
import type { PaidReferralFormValues } from '../schema/paidReferralSchema';
import type { ClCareLevel, ClUrgency, FeeStatus } from '../constants/clReferralsApiConstants';

// Postgres numeric arrives as a string — coerce for display.
export const num = (v: number | string | null | undefined): number =>
  v == null || v === '' ? 0 : Number(v);

export function toCreatePaidReferral(v: PaidReferralFormValues): CreateClPaidReferralRequest {
  return {
    prospectName: v.prospectName.trim(),
    sourceName: v.sourceName.trim(),
    careLevel: v.careLevel as ClCareLevel,
    urgency: v.urgency as ClUrgency,
    feeStatus: v.feeStatus as FeeStatus,
    ...opt('prospectPhone', v.prospectPhone),
    ...(v.referralFee?.trim() ? { referralFee: Number(v.referralFee) } : {}),
    ...opt('stage', v.stage),
  };
}

export function toUpdatePaidReferral(
  v: PaidReferralFormValues,
): Partial<CreateClPaidReferralRequest> {
  return toCreatePaidReferral(v);
}

export function toPaidReferralFormValues(r: ClPaidReferralRecord): PaidReferralFormValues {
  return {
    prospectName: r.prospectName,
    prospectPhone: r.prospectPhone ?? '',
    careLevel: (r.careLevel ?? 'IL') as PaidReferralFormValues['careLevel'],
    urgency: r.urgency,
    sourceName: r.sourceName,
    referralFee: r.referralFee != null ? String(num(r.referralFee)) : '',
    feeStatus: r.feeStatus,
    stage: r.stage ?? '',
  };
}
