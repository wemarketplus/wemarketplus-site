import type { ID, ISODateString, PaginationParams } from '@/shared/types';
import type { LocationStatus } from '../constants/locationsConstants';

// Mirrors wemarketplus-backend/src/locations/dto/location-response.dto.ts.
export interface LocationRecord {
  id: ID;
  tenantId: ID;
  locationName: string;
  state: string | null;
  county: string | null;
  city: string | null;
  status: LocationStatus;
  employeeCount: number | null;
  companyId: ID | null;
  address: string | null;
  notes: string | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateLocationRequest {
  locationName: string;
  state?: string;
  county?: string;
  city?: string;
  status?: LocationStatus;
  employeeCount?: number;
  companyId?: string;
  address?: string;
  notes?: string;
}

export type UpdateLocationRequest = Partial<CreateLocationRequest>;

export interface ListLocationsQuery extends PaginationParams {
  state?: string;
  status?: LocationStatus;
  search?: string;
}
