import type { ID, ISODateString } from '@/shared/types';
import type { AgreementStatus, ContractStatus } from '../constants/agreementsConstants';

// Mirrors wemarketplus-backend/src/agreements + contracts response DTOs.
export interface AgreementRecord {
  id: ID;
  tenantId: ID;
  agreementName: string;
  companyName: string | null;
  counterparty: string | null;
  status: AgreementStatus;
  effectiveDate: string | null;
  expirationDate: string | null;
  value: number | null;
  agreementType: string | null;
  notes: string | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateAgreementRequest {
  agreementName?: string;
  title?: string;
  companyName?: string;
  counterparty?: string;
  value?: number;
  status?: AgreementStatus;
  effectiveDate?: string;
  expirationDate?: string;
  agreementType?: string;
  notes?: string;
}

export interface ContractRecord {
  id: ID;
  tenantId: ID;
  contractNumber: string;
  companyName: string;
  contractType: string | null;
  value: number | null;
  status: ContractStatus;
  signedDate: string | null;
  expiryDate: string | null;
  notes: string | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateContractRequest {
  companyName: string;
  contractNumber?: string;
  contractType?: string;
  value?: number;
  status?: ContractStatus;
  signedDate?: string;
  expiryDate?: string;
  notes?: string;
}
