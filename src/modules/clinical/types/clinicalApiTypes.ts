import type { ID, ISODateString } from '@/shared/types';
import type { BedUnitStatus, TelehealthStatus } from '../constants/clinicalStatus';

// Backend record shapes for clinical/field workflows — wemarketplus-backend
// evv-logs, telehealth-sessions, bed-units, gift-gratuity-logs, alert-settings.
interface Base {
  id: ID;
  tenantId: ID;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface EvvLogRecord extends Base {
  userId: ID;
  prospectId: ID | null;
  clockIn: ISODateString | null;
  clockOut: ISODateString | null;
  locationIn: string | null;
  visitType: string | null;
  notes: string | null;
}
export interface ClockInRequest {
  prospectId?: string;
  locationIn?: string;
  visitType?: string;
  notes?: string;
}
export interface ClockOutRequest {
  locationOut?: string;
  notes?: string;
}

export interface TelehealthSessionRecord extends Base {
  prospectId: ID | null;
  patientName: string;
  providerName: string | null;
  sessionType: string | null;
  scheduledAt: ISODateString;
  durationMin: number | null;
  status: TelehealthStatus;
  notes: string | null;
}
export interface CreateTelehealthSessionRequest {
  patientName: string;
  scheduledAt: string;
  prospectId?: string;
  providerName?: string;
  sessionType?: string;
  durationMin?: number;
  status?: TelehealthStatus;
  notes?: string;
}

export interface BedUnitRecord extends Base {
  facilityName: string;
  bedType: string | null;
  status: BedUnitStatus;
  patientName: string | null;
  notes: string | null;
}
export interface CreateBedUnitRequest {
  facilityName: string;
  bedType?: string;
  status?: BedUnitStatus;
  patientName?: string;
  notes?: string;
}

export interface GiftGratuityRecord extends Base {
  recipientName: string;
  facilityName: string | null;
  referralSource: string | null;
  visitDate: string;
  giftType: string;
  giftValue: number;
  visitPurpose: string | null;
  notes: string | null;
}
export interface CreateGiftGratuityRequest {
  recipientName: string;
  visitDate: string;
  giftType: string;
  giftValue: number;
  facilityName?: string;
  referralSource?: string;
  visitPurpose?: string;
  notes?: string;
}

export interface AlertSetting {
  id: ID;
  tenantId: ID;
  alertType: string;
  enabled: boolean;
  recipientRoles: string[] | null;
  recipientUserIds: string[] | null;
  channel: string;
  updatedAt: ISODateString;
}
