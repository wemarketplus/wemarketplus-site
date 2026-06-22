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
