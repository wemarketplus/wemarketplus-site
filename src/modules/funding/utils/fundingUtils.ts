import { optNumOrNull, optOrNull } from '@/shared/ui/entity';
import type { FundingStatus } from '../constants/fundingConstants';
import type {
  CreateFundingRequest,
  FundingRecord,
  UpdateFundingRequest,
} from '../types/fundingTypes';
import type { FundingFormValues } from '../schema/fundingSchema';

// Form values -> POST /funding body. Blank optionals go as explicit nulls, not
// omitted keys, so clearing one in the edit form actually clears the column
// (every field below is nullable). `status` stays conditional: its column is NOT
// NULL with a DB default.
export function toCreateFunding(values: FundingFormValues): CreateFundingRequest {
  return {
    opportunityName: values.opportunityName.trim(),
    sourceUrl: values.sourceUrl.trim(),
    ...(values.status ? { status: values.status as FundingStatus } : {}),
    ...optOrNull('programType', values.programType),
    ...optNumOrNull('maxAwardPerEin', values.maxAwardPerEin),
    ...optOrNull('applicationDeadline', values.applicationDeadline),
    ...optOrNull('applicationLink', values.applicationLink),
    ...optOrNull('notes', values.notes),
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
