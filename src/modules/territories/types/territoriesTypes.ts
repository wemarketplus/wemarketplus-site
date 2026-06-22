import type { ID, ISODateString } from '@/shared/types';
import type { TerritoryPriority } from '../constants/territoriesConstants';

// Mirrors wemarketplus-backend/src/territories/dto/territory-response.dto.ts.
export interface TerritoryRecord {
  id: ID;
  tenantId: ID;
  name: string;
  city: string | null;
  state: string | null;
  zipCodes: string[] | null;
  assignedTo: ID | null;
  priority: TerritoryPriority;
  notes: string | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateTerritoryRequest {
  name: string;
  city?: string;
  state?: string;
  zipCodes?: string[];
  assignedTo?: string;
  priority?: TerritoryPriority;
  notes?: string;
}

export type UpdateTerritoryRequest = Partial<CreateTerritoryRequest>;
