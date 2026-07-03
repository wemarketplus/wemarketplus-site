import type { ID, ISODateString, PaginationParams } from '@/shared/types';

// Backend platform owner-portal record shapes — wemarketplus-backend/src/owner-portal.
export interface OwnerMetrics {
  pipelineByStage: { stage: string; count: number }[];
  totalPipeline: number;
}

// Backend TenantResponseDto (owner-portal listCustomers / suspendCustomer).
export interface OwnerCustomer {
  id: ID;
  name: string;
  city: string | null;
  state: string | null;
  phone: string | null;
  product: string;
  crmTier: string;
  package: string;
  subscriptionStatus: string;
  isActive: boolean;
  baaSigned: boolean;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface PipelineRecord {
  id: ID;
  name: string;
  company: string | null;
  email: string | null;
  phone: string | null;
  productInterest: string | null;
  source: string | null;
  stage: string;
  conversionPct: number;
  stripeStatus: string | null;
  notes: string | null;
  lastActivity: ISODateString | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreatePipelineRecordRequest {
  name: string;
  company?: string;
  email?: string;
  phone?: string;
  productInterest?: string;
  source?: string;
  stage?: string;
  conversionPct?: number;
}

export type UpdatePipelineRecordRequest = Partial<CreatePipelineRecordRequest> & {
  stripeStatus?: string;
  notes?: string;
};

export interface ListPipelineQuery extends PaginationParams {
  stage?: string;
}
