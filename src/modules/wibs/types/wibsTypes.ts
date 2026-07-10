import type { ID, ISODateString, PaginationParams } from '@/shared/types';
import type { WibStatus } from '../constants/wibsConstants';

// Mirrors wemarketplus-backend/src/wibs/dto/wib-response.dto.ts.
export interface WibRecord {
  id: ID;
  tenantId: ID;
  wibName: string;
  shortName: string | null;
  state: string | null;
  status: WibStatus;
  wibPhone: string | null;
  wibEmail: string | null;
  website: string | null;
  sourceUrl: string | null;
  maxAwardPerEin: number | null;
  matchRequirementPct: number | null;
  wibType: string | null;
  googleDriveFolderUrl: string | null;
  nextSteps: string | null;
  blockers: string | null;
  notes: string | null;
  iwtProgramActive: boolean;
  independentCreationLogged: boolean;
  lastVerifiedDate: string | null;
  callPriorityScore: number;
  ownerId: ID | null;
  territoryId: ID | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateWibRequest {
  wibName: string;
  sourceUrl: string;
  shortName?: string;
  state?: string;
  status?: WibStatus;
  wibPhone?: string;
  wibEmail?: string;
  website?: string;
  maxAwardPerEin?: number;
  matchRequirementPct?: number;
  wibType?: string;
  nextSteps?: string;
  blockers?: string;
  notes?: string;
}

export type UpdateWibRequest = Partial<CreateWibRequest>;

export interface ListWibsQuery extends PaginationParams {
  state?: string;
  status?: WibStatus;
  search?: string;
}

export interface WibViewPref {
  viewMode: string;
}
