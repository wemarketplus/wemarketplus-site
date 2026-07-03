import { opt, optNum } from '@/shared/ui/entity';
import type { ApplicationStatus } from '../constants/applicationsConstants';
import type {
  ApplicationRecord,
  CreateApplicationRequest,
  UpdateApplicationRequest,
} from '../types/applicationsTypes';
import type { ApplicationFormValues } from '../schema/applicationSchema';

// Form values -> POST /applications. companyId + wibId are required UUIDs; the
// rest are optional and stripped when blank.
export function toCreateApplication(values: ApplicationFormValues): CreateApplicationRequest {
  return {
    companyId: values.companyId.trim(),
    wibId: values.wibId.trim(),
    ...opt('fundingOpportunityId', values.fundingOpportunityId),
    ...(values.status ? { status: values.status as ApplicationStatus } : {}),
    ...optNum('awardAmountRequested', values.awardAmountRequested),
    ...opt('submissionDate', values.submissionDate),
    ...opt('notes', values.notes),
  };
}

// PATCH body — the update whitelist excludes company/wib/funding references (not
// reassignable) and adds awardAmountApproved + decisionDate.
export function toUpdateApplication(values: ApplicationFormValues): UpdateApplicationRequest {
  return {
    ...(values.status ? { status: values.status as ApplicationStatus } : {}),
    ...optNum('awardAmountRequested', values.awardAmountRequested),
    ...optNum('awardAmountApproved', values.awardAmountApproved),
    ...opt('submissionDate', values.submissionDate),
    ...opt('decisionDate', values.decisionDate),
    ...opt('notes', values.notes),
  };
}

// Seeds the edit form from an existing record (nulls -> '' / undefined).
export function toApplicationFormValues(record: ApplicationRecord): ApplicationFormValues {
  return {
    companyId: record.companyId,
    wibId: record.wibId,
    fundingOpportunityId: record.fundingOpportunityId ?? '',
    status: record.status,
    awardAmountRequested: record.awardAmountRequested ?? undefined,
    awardAmountApproved: record.awardAmountApproved ?? undefined,
    submissionDate: record.submissionDate ?? '',
    decisionDate: record.decisionDate ?? '',
    notes: record.notes ?? '',
  };
}
