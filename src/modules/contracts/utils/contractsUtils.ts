import { opt, optNum } from '@/shared/ui/entity';
import type { CreateContractRequest, UpdateContractRequest } from '../types/contractsTypes';
import type { ContractFormValues } from '../schema/contractSchema';
import type { ContractRecord } from '../types/contractsTypes';
import type { ContractStatus } from '../constants/contractsConstants';

// Form values -> POST /contracts body. Drops blank optionals so we never send
// empty strings the DTO would reject. value is dropped when blank/NaN.
export function toCreateContract(values: ContractFormValues): CreateContractRequest {
  return {
    companyName: values.companyName.trim(),
    ...opt('contractType', values.contractType),
    ...opt('contractNumber', values.contractNumber),
    ...opt('signedDate', values.signedDate),
    ...opt('expiryDate', values.expiryDate),
    ...opt('notes', values.notes),
    ...optNum('value', values.value),
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
