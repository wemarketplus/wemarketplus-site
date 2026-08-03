import type { ID, ISODateString, PaginationParams } from '@/shared/types';
import type { ApplicationStatus } from '../constants/applicationsConstants';

// Mirrors wemarketplus-backend/src/applications/dto/application-response.dto.ts.
export interface ApplicationRecord {
  id: ID;
  tenantId: ID;
  applicationNumber: string | null;
  companyId: ID;
  fundingOpportunityId: ID | null;
  status: ApplicationStatus;
  awardAmountRequested: number | null;
  awardAmountApproved: number | null;
  submissionDate: string | null;
  decisionDate: string | null;
  notes: string | null;
  ownerId: ID | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateApplicationRequest {
  companyId: string;
  fundingOpportunityId?: string;
  status?: ApplicationStatus;
  awardAmountRequested?: number;
  submissionDate?: string;
  notes?: string;
}

export type UpdateApplicationRequest = Partial<CreateApplicationRequest> & {
  awardAmountApproved?: number;
  decisionDate?: string;
};

export interface ListApplicationsQuery extends PaginationParams {
  status?: ApplicationStatus;
}
