import type { ID, ISODateString, PaginationParams } from '@/shared/types';
import type { CompletionStatus, TrainingProviderStatus } from '../constants/trainingConstants';

// Mirrors wemarketplus-backend/src/training-providers + training-rosters DTOs.
export interface TrainingProviderRecord {
  id: ID;
  tenantId: ID;
  name: string;
  providerType: string | null;
  website: string | null;
  contactEmail: string | null;
  contactPhone: string | null;
  programs: string | null;
  state: string | null;
  notes: string | null;
  status: TrainingProviderStatus;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateTrainingProviderRequest {
  name: string;
  providerType?: string;
  website?: string;
  contactEmail?: string;
  contactPhone?: string;
  programs?: string;
  state?: string;
  notes?: string;
  status?: TrainingProviderStatus;
}

export interface RosterRecord {
  id: ID;
  tenantId: ID;
  applicationId: ID;
  companyId: ID | null;
  participantName: string;
  participantEmail: string | null;
  participantPhone: string | null;
  trainingStartDate: string | null;
  trainingEndDate: string | null;
  trainingProgram: string | null;
  completionStatus: CompletionStatus;
  attendancePct: number | null;
  wagePreTraining: number | null;
  wagePostTraining: number | null;
  notes: string | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateRosterRequest {
  applicationId: string;
  participantName: string;
  companyId?: string;
  participantEmail?: string;
  participantPhone?: string;
  trainingStartDate?: string;
  trainingEndDate?: string;
  trainingProgram?: string;
  completionStatus?: CompletionStatus;
  attendancePct?: number;
  wagePreTraining?: number;
  wagePostTraining?: number;
  notes?: string;
}

export interface ListRostersQuery extends PaginationParams {
  applicationId?: string;
  companyId?: string;
  status?: CompletionStatus;
}
