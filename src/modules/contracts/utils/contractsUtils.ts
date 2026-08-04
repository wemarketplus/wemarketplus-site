import { opt, optNumOrNull, optOrNull } from '@/shared/ui/entity';
import type { CreateContractRequest, UpdateContractRequest } from '../types/contractsTypes';
import type { ContractFormValues } from '../schema/contractSchema';
import type { ContractRecord } from '../types/contractsTypes';
import type { ContractStatus } from '../constants/contractsConstants';

// Form values -> POST /contracts body. Nullable optionals go as explicit nulls so
// clearing one in the edit form actually clears the column — an omitted key in a
// PATCH means "leave unchanged".
//
// contractNumber is the exception and MUST stay `opt`: its column is NOT NULL and
// the service fills it with `dto.contractNumber ?? generateContractNumber()`. An
// absent key generates one; an explicit null slips past `??` on create but
// violates NOT NULL on update. status is likewise NOT NULL with a DB default.
export function toCreateContract(values: ContractFormValues): CreateContractRequest {
  return {
    companyName: values.companyName.trim(),
    ...optOrNull('contractType', values.contractType),
    ...opt('contractNumber', values.contractNumber),
    ...optOrNull('signedDate', values.signedDate),
    ...optOrNull('expiryDate', values.expiryDate),
    ...optOrNull('notes', values.notes),
    ...optNumOrNull('value', values.value),
    ...(values.status ? { status: values.status as ContractStatus } : {}),
  };
}

// PATCH body is the same shape (partial); the backend accepts any subset.
export function toUpdateContract(values: ContractFormValues): UpdateContractRequest {
  return toCreateContract(values);
}

// Seeds the edit form from an existing record (nulls -> '').
export function toContractFormValues(contract: ContractRecord): ContractFormValues {
  return {
    companyName: contract.companyName,
    contractType: contract.contractType ?? '',
    value: contract.value ?? undefined,
    status: contract.status,
    contractNumber: contract.contractNumber ?? '',
    signedDate: contract.signedDate ?? '',
    expiryDate: contract.expiryDate ?? '',
    notes: contract.notes ?? '',
  };
}

// USD money formatter shared across the contracts table.
const MONEY = new Intl.NumberFormat('en-US', {
  style: 'currency',
  currency: 'USD',
});
export const formatMoney = (value: number | null): string =>
  value === null ? '—' : MONEY.format(value);
