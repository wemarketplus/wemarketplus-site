import type { ID, ISODateString, PaginationParams } from '@/shared/types';
import type { FundingStatus } from '../constants/fundingConstants';

// Mirrors wemarketplus-backend/src/funding/dto/funding-response.dto.ts.
export interface FundingRecord {
  id: ID;
  tenantId: ID;
  opportunityName: string;
  status: FundingStatus;
  programType: string | null;
  maxAwardPerEin: number | null;
  applicationDeadline: string | null;
  applicationLink: string | null;
  sourceUrl: string | null;
  notes: string | null;
  independentCreationLogged: boolean;
  lastVerifiedDate: string | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateFundingRequest {
  opportunityName: string;
  sourceUrl: string;
  status?: FundingStatus;
  programType?: string;
  maxAwardPerEin?: number;
  applicationDeadline?: string;
  applicationLink?: string;
  notes?: string;
}

export type UpdateFundingRequest = Partial<CreateFundingRequest>;

export interface ListFundingQuery extends PaginationParams {
  status?: FundingStatus;
  search?: string;
}
