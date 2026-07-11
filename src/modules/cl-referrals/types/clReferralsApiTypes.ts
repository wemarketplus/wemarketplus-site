import type { ID, ISODateString } from '@/shared/types';
import type { ClCareLevel, ClUrgency, FeeStatus } from '../constants/clReferralsApiConstants';

// Backend record shapes for CommunityLink referrals — wemarketplus-backend
// cl/referral-sources, cl/paid-referrals.
export interface ClReferralSourceRecord {
  id: ID;
  tenantId: ID;
  name: string;
  organization: string | null;
  type: string | null;
  phone: string | null;
  email: string | null;
  address: string | null;
  referralCount: number;
  lastReferralDate: string | null;
  notes: string | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateClReferralSourceRequest {
  name: string;
  organization?: string;
  type?: string;
  phone?: string;
  email?: string;
  address?: string;
  lastReferralDate?: string;
  notes?: string;
}

export interface ClPaidReferralRecord {
  id: ID;
  tenantId: ID;
  prospectName: string;
  prospectPhone: string | null;
  prospectEmail: string | null;
  careLevel: ClCareLevel | null;
  sourceName: string;
  referralFee: number | null;
  feeStatus: FeeStatus;
  urgency: ClUrgency;
  stage: string | null;
  assignedTo: ID | null;
  leadId: ID | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateClPaidReferralRequest {
  prospectName: string;
  prospectPhone?: string;
  prospectEmail?: string;
  budgetRange?: string;
  moveInTimeframe?: string;
  careNeeds?: string;
  careLevel?: ClCareLevel;
  preferredLocation?: string;
  sourceName: string;
  sourceContact?: string;
  referralFee?: number;
  feeStatus?: FeeStatus;
  urgency?: ClUrgency;
  stage?: string;
  assignedTo?: string;
  leadId?: string;
}
