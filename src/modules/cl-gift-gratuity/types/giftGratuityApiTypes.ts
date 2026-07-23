import type { ID, ISODateString } from '@/shared/types';

// wemarketplus-backend/src/gift-gratuity — append-only compliance log.
export interface GiftGratuityLogRecord {
  id: ID;
  tenantId: ID;
  userId: ID;
  recipientName: string;
  facilityName: string | null;
  referralSource: string | null;
  visitDate: string;
  giftType: string;
  giftValue: number;
  visitPurpose: string | null;
  notes: string | null;
  complianceOk: boolean;
  limitAtTime: number;
  createdAt: ISODateString;
}

export interface CreateGiftGratuityLogRequest {
  recipientName: string;
  facilityName?: string;
  referralSource?: string;
  visitDate: string;
  giftType: string;
  giftValue: number;
  visitPurpose?: string;
  notes?: string;
}
