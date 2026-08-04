import type { EntityField, EntitySelectOption } from '@/shared/ui/entity';
import type { AgreementFormValues } from '../schema/agreementSchema';

// Agreement + contract status enums — mirror backend AgreementStatus/ContractStatus.
export const AGREEMENT_STATUS = {
  Draft: 'draft',
  PendingSignature: 'pending_signature',
  Signed: 'signed',
  Active: 'active',
  Expired: 'expired',
  Terminated: 'terminated',
} as const;
export type AgreementStatus = (typeof AGREEMENT_STATUS)[keyof typeof AGREEMENT_STATUS];

export const CONTRACT_STATUS = {
  Draft: 'draft',
  Active: 'active',
  Signed: 'signed',
  Expired: 'expired',
  Terminated: 'terminated',
} as const;
export type ContractStatus = (typeof CONTRACT_STATUS)[keyof typeof CONTRACT_STATUS];

export const AGREEMENTS_PAGE_SIZE = 20;

// Title Case labels for the agreement status enum values.
export const AGREEMENT_STATUS_LABELS: Record<AgreementStatus, string> = {
  draft: 'Draft',
  pending_signature: 'Pending signature',
  signed: 'Signed',
  active: 'Active',
  expired: 'Expired',
  terminated: 'Terminated',
};

const STATUS_OPTIONS: ReadonlyArray<EntitySelectOption> = [
  { value: '', label: 'Select status…' },
  ...Object.values(AGREEMENT_STATUS).map((v) => ({ value: v, label: AGREEMENT_STATUS_LABELS[v] })),
];

// Field descriptors driving the create/edit modal (EntityFormModal).
export const AGREEMENT_FIELDS: ReadonlyArray<EntityField<AgreementFormValues>> = [
  { name: 'agreementName', label: 'Agreement name', full: true, placeholder: 'Master services agreement' },
  { name: 'companyName', label: 'Company', placeholder: 'Acme Corp' },
  { name: 'counterparty', label: 'Counterparty', placeholder: 'Counterparty name' },
  { name: 'agreementType', label: 'Type', placeholder: 'MSA, NDA…' },
  { name: 'status', label: 'Status', type: 'select', options: STATUS_OPTIONS },
  { name: 'value', label: 'Value', type: 'number', placeholder: '0' },
  { name: 'effectiveDate', label: 'Effective date', type: 'date' },
  { name: 'expirationDate', label: 'Expiration date', type: 'date' },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true },
];
