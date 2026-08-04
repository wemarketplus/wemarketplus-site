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

// `null` on an optional field means "clear this column"; an omitted key means
// "leave unchanged" — see optOrNull in shared/ui/entity/formValues.
export interface CreateApplicationRequest {
  companyId: string;
  fundingOpportunityId?: string | null;
  status?: ApplicationStatus;
  awardAmountRequested?: number | null;
  submissionDate?: string | null;
  notes?: string | null;
}

export type UpdateApplicationRequest = Partial<CreateApplicationRequest> & {
  awardAmountApproved?: number | null;
  decisionDate?: string | null;
};

export interface ListApplicationsQuery extends PaginationParams {
  status?: ApplicationStatus;
}
