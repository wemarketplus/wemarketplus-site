import { opt, optNum } from '@/shared/ui/entity';
import type { AgreementStatus } from '../constants/agreementsConstants';
import type { AgreementRecord, CreateAgreementRequest } from '../types/agreementsTypes';
import type { AgreementFormValues } from '../schema/agreementSchema';

// Form values -> POST /agreements body. We always send the canonical
// `agreementName` + `value` (the backend also accepts title/amount aliases).
export function toCreateAgreement(values: AgreementFormValues): CreateAgreementRequest {
  return {
    agreementName: values.agreementName.trim(),
    ...opt('companyName', values.companyName),
    ...opt('counterparty', values.counterparty),
    ...opt('agreementType', values.agreementType),
    ...(values.status ? { status: values.status as AgreementStatus } : {}),
    ...optNum('value', values.value),
    ...opt('effectiveDate', values.effectiveDate),
    ...opt('expirationDate', values.expirationDate),
    ...opt('notes', values.notes),
  };
}

// PATCH body is the same whitelisted shape (partial merge on the backend).
export function toUpdateAgreement(values: AgreementFormValues): Partial<CreateAgreementRequest> {
  return toCreateAgreement(values);
}

// Seeds the edit form from an existing record (nulls -> '' / undefined).
export function toAgreementFormValues(record: AgreementRecord): AgreementFormValues {
  return {
    agreementName: record.agreementName,
    companyName: record.companyName ?? '',
    counterparty: record.counterparty ?? '',
    agreementType: record.agreementType ?? '',
    status: record.status,
    value: record.value ?? undefined,
    effectiveDate: record.effectiveDate ?? '',
    expirationDate: record.expirationDate ?? '',
    notes: record.notes ?? '',
  };
}
