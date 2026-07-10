import type { EntityField } from '@/shared/ui/entity';
import type { ContractFormValues } from '../schema/contractSchema';

export const CONTRACTS_PAGE_SIZE = 20;

// Mirrors backend ContractStatus (contracts/entities/contract.entity.ts).
export const CONTRACT_STATUS = {
  Draft: 'draft',
  Active: 'active',
  Signed: 'signed',
  Expired: 'expired',
  Terminated: 'terminated',
} as const;
export type ContractStatus = (typeof CONTRACT_STATUS)[keyof typeof CONTRACT_STATUS];

export const CONTRACT_STATUS_OPTIONS: ReadonlyArray<{ value: ContractStatus; label: string }> = [
  { value: 'draft', label: 'Draft' },
  { value: 'active', label: 'Active' },
  { value: 'signed', label: 'Signed' },
  { value: 'expired', label: 'Expired' },
  { value: 'terminated', label: 'Terminated' },
];

// Field descriptors driving the create/edit modal (EntityFormModal). Order here
// is render order; `full` spans both grid columns. contractNumber is optional
// (auto-generated when blank).
export const CONTRACT_FIELDS: ReadonlyArray<EntityField<ContractFormValues>> = [
  { name: 'companyName', label: 'Company', full: true, placeholder: 'Acme Corp' },
  { name: 'contractType', label: 'Type', placeholder: 'service, MSA…' },
  { name: 'value', label: 'Value', type: 'number', placeholder: '0.00' },
  {
    name: 'status',
    label: 'Status',
    type: 'select',
    options: CONTRACT_STATUS_OPTIONS.map((o) => ({ value: o.value, label: o.label })),
  },
  { name: 'contractNumber', label: 'Contract number', placeholder: 'auto-generated' },
  { name: 'signedDate', label: 'Signed date', placeholder: 'YYYY-MM-DD' },
  { name: 'expiryDate', label: 'Expiry date', placeholder: 'YYYY-MM-DD' },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true },
];
