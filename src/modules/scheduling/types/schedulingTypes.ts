import type { ID, ISODateString, Territory } from '@/shared/types';

// Retained from before this module gained a data layer: the territory views still exist
// on the same slice, so their types must keep being exported.
export type { Territory };

export interface SchedulingUiState {
  view: 'territories' | 'heatmap';
}

// Mirrors wemarketplus-backend/src/nurse-scheduling/dto/nurse-shift-response.dto.ts.
export type NurseShiftType = 'visit' | 'on_call' | 'admin';
export type NurseShiftStatus =
  | 'scheduled'
  | 'confirmed'
  | 'completed'
  | 'cancelled';

export interface NurseShiftRecord {
  id: ID;
  tenantId: ID;
  nurseId: ID;
  /** Plain YYYY-MM-DD — a `date` column, not an instant. Do not timezone-convert it. */
  date: string;
  startTime: string;
  endTime: string;
  shiftType: NurseShiftType;
  status: NurseShiftStatus;
  appointmentId: ID | null;
  notes: string | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateNurseShiftRequest {
  nurseId: string;
  date: string;
  startTime: string;
  endTime: string;
  shiftType?: NurseShiftType;
  status?: NurseShiftStatus;
  appointmentId?: string;
  notes?: string;
}

export type UpdateNurseShiftRequest = Partial<CreateNurseShiftRequest>;

export interface CoverageDay {
  date: string;
  nurses: number;
  visitMinutes: number;
  onCallMinutes: number;
  adminMinutes: number;
  appointments: number;
  coveredAppointments: number;
  /** Visits with nobody rostered against them — the number the screen exists for. */
  uncoveredAppointments: number;
}

export interface CoverageResponse {
  from: string;
  to: string;
  days: CoverageDay[];
  totalUncovered: number;
}

export const SHIFT_TYPE_LABELS: Record<NurseShiftType, string> = {
  visit: 'Visits',
  on_call: 'On call',
  admin: 'Admin',
};
