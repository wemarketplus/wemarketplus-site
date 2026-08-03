import { opt, optNum } from '@/shared/ui/entity';
import type { FundingStatus } from '../constants/fundingConstants';
import type {
  CreateFundingRequest,
  FundingRecord,
  UpdateFundingRequest,
} from '../types/fundingTypes';
import type { FundingFormValues } from '../schema/fundingSchema';

// Form values -> POST /funding body. Drops blank optionals so we never send an
// empty string where the DTO expects an absent field.
export function toCreateFunding(values: FundingFormValues): CreateFundingRequest {
  return {
    opportunityName: values.opportunityName.trim(),
    sourceUrl: values.sourceUrl.trim(),
    ...(values.status ? { status: values.status as FundingStatus } : {}),
    ...opt('programType', values.programType),
    ...optNum('maxAwardPerEin', values.maxAwardPerEin),
    ...opt('applicationDeadline', values.applicationDeadline),
    ...opt('applicationLink', values.applicationLink),
    ...opt('notes', values.notes),
  };
}

// PATCH body. Create and update now accept the same fields — the only field the
// update whitelist rejected was `wibId` (creation-only), and WIB has been removed
// from this product entirely.
export function toUpdateFunding(values: FundingFormValues): UpdateFundingRequest {
  return toCreateFunding(values);
}

// Seeds the edit form from an existing record (nulls -> '').
export function toFundingFormValues(record: FundingRecord): FundingFormValues {
  return {
    opportunityName: record.opportunityName,
    sourceUrl: record.sourceUrl ?? '',
    status: record.status,
    programType: record.programType ?? '',
    maxAwardPerEin: record.maxAwardPerEin ?? undefined,
    applicationDeadline: record.applicationDeadline ?? '',
    applicationLink: record.applicationLink ?? '',
    notes: record.notes ?? '',
  };
}
