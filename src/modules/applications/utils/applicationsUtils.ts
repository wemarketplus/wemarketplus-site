import { optNumOrNull, optOrNull } from '@/shared/ui/entity';
import type { ApplicationStatus } from '../constants/applicationsConstants';
import type {
  ApplicationRecord,
  CreateApplicationRequest,
  UpdateApplicationRequest,
} from '../types/applicationsTypes';
import type { ApplicationFormValues } from '../schema/applicationSchema';

// Form values -> POST /applications. companyId is a required reference; the rest
// are nullable, so a blank goes as an explicit null rather than an omitted key —
// otherwise clearing one in the edit form silently kept the stored value.
// `status` stays conditional: its column is NOT NULL with a DB default.
export function toCreateApplication(values: ApplicationFormValues): CreateApplicationRequest {
  return {
    companyId: values.companyId.trim(),
    ...optOrNull('fundingOpportunityId', values.fundingOpportunityId),
    ...(values.status ? { status: values.status as ApplicationStatus } : {}),
    ...optNumOrNull('awardAmountRequested', values.awardAmountRequested),
    ...optOrNull('submissionDate', values.submissionDate),
    ...optOrNull('notes', values.notes),
  };
}

// PATCH body — the update whitelist excludes company/funding references (not
// reassignable) and adds awardAmountApproved + decisionDate.
export function toUpdateApplication(values: ApplicationFormValues): UpdateApplicationRequest {
  return {
    ...(values.status ? { status: values.status as ApplicationStatus } : {}),
    ...optNumOrNull('awardAmountRequested', values.awardAmountRequested),
    ...optNumOrNull('awardAmountApproved', values.awardAmountApproved),
    ...optOrNull('submissionDate', values.submissionDate),
    ...optOrNull('decisionDate', values.decisionDate),
    ...optOrNull('notes', values.notes),
  };
}

// Seeds the edit form from an existing record (nulls -> '' / undefined).
export function toApplicationFormValues(record: ApplicationRecord): ApplicationFormValues {
  return {
    companyId: record.companyId,
    fundingOpportunityId: record.fundingOpportunityId ?? '',
    status: record.status,
    awardAmountRequested: record.awardAmountRequested ?? undefined,
    awardAmountApproved: record.awardAmountApproved ?? undefined,
    submissionDate: record.submissionDate ?? '',
    decisionDate: record.decisionDate ?? '',
    notes: record.notes ?? '',
  };
}
