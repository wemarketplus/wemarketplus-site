import type { ID, ISODateString, PaginationParams } from '@/shared/types';
import type { ContractStatus } from '../constants/contractsConstants';

// Mirrors wemarketplus-backend/src/contracts/dto/contract-response.dto.ts.
// Contracts are tenant-scoped. `contractNumber` is auto-generated server-side
// (CTR-<last 6 of Date.now()>) when omitted on create.
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

// Mirrors CreateContractDto — companyName required, rest optional.
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

// Mirrors UpdateContractDto — any subset of the create fields.
export type UpdateContractRequest = Partial<CreateContractRequest>;

// GET /contracts is pagination-only (no filters on the backend).
export type ListContractsQuery = PaginationParams;
