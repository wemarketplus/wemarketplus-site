import type { ID, ISODateString } from '@/shared/types';

// Mirrors wemarketplus-backend/src/mileage/entities/mileage-log.entity.ts and its
// create/update DTOs. `date` is a DATE column, so it is a plain YYYY-MM-DD string,
// not an instant — do not pass it through a timezone conversion.
export interface MileageLogRecord {
  id: ID;
  tenantId: ID;
  userId: ID;
  date: string;
  fromLocation: string | null;
  toLocation: string | null;
  purpose: string | null;
  miles: number;
  reimbursementRate: number;
  reimbursementAmount: number | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateMileageLogRequest {
  date?: string;
  fromLocation?: string;
  toLocation?: string;
  purpose?: string;
  miles: number;
  reimbursementRate?: number;
}

export type UpdateMileageLogRequest = Partial<CreateMileageLogRequest>;

/** UI state for the field screens. */
export interface FieldUiState {
  /** The EVV log row currently clocked in, so the page can offer clock-out. */
  openVisitId: ID | null;
}
