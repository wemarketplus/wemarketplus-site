import { opt, optNum } from '@/shared/ui/entity';
import type { FundingStatus } from '../constants/fundingConstants';
import type {
  CreateFundingRequest,
  FundingRecord,
  UpdateFundingRequest,
} from '../types/fundingTypes';
import type { FundingFormValues } from '../schema/fundingSchema';

// Form values -> POST /funding body. Drops blank optionals so we never send
// empty strings the DTO rejects (wibId/applicationLink are IsUUID/IsUrl gated).
export function toCreateFunding(values: FundingFormValues): CreateFundingRequest {
  return {
    opportunityName: values.opportunityName.trim(),
    sourceUrl: values.sourceUrl.trim(),
    ...opt('wibId', values.wibId),
    ...(values.status ? { status: values.status as FundingStatus } : {}),
    ...opt('programType', values.programType),
    ...optNum('maxAwardPerEin', values.maxAwardPerEin),
    ...opt('applicationDeadline', values.applicationDeadline),
    ...opt('applicationLink', values.applicationLink),
    ...opt('notes', values.notes),
  };
}

// PATCH body — the backend update whitelist is NARROWER than create: it does not
// accept `wibId` (set only at creation). Drop it here so an edit never 400s.
export function toUpdateFunding(values: FundingFormValues): UpdateFundingRequest {
  const { wibId: _wibId, ...rest } = toCreateFunding(values);
  return rest;
}

// Seeds the edit form from an existing record (nulls -> '').
export function toFundingFormValues(record: FundingRecord): FundingFormValues {
  return {
    opportunityName: record.opportunityName,
    sourceUrl: record.sourceUrl ?? '',
    wibId: record.wibId ?? '',
    status: record.status,
    programType: record.programType ?? '',
    maxAwardPerEin: record.maxAwardPerEin ?? undefined,
    applicationDeadline: record.applicationDeadline ?? '',
    applicationLink: record.applicationLink ?? '',
    notes: record.notes ?? '',
  };
}
