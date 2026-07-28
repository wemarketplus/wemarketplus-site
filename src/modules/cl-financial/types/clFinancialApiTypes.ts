import type { ID, ISODateString } from '@/shared/types';
import type { ConcessionStatus, LeakageStatus } from '../constants/clFinancialApiConstants';

// Backend record shapes for the CommunityLink financial command centre —
// wemarketplus-backend cl/revenue-entries, cl/concessions, cl/competitors,
// cl/loc-pricing.
export interface ClRevenueEntryRecord {
  id: ID;
  tenantId: ID;
  apartmentId: ID | null;
  entryDate: string;
  category: string | null;
  amount: number;
  description: string | null;
  budgetAmount: number | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateClRevenueEntryRequest {
  apartmentId?: string;
  entryDate: string;
  category?: string;
  amount: number;
  description?: string;
  budgetAmount?: number;
}

export interface ClConcessionRecord {
  id: ID;
  tenantId: ID;
  apartmentId: ID | null;
  leadId: ID | null;
  type: string;
  valueAmount: number | null;
  status: ConcessionStatus;
  reason: string | null;
  decisionNote: string | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateClConcessionRequest {
  apartmentId?: string;
  leadId?: string;
  type: string;
  valueAmount?: number;
  status?: ConcessionStatus;
  reason?: string;
  decisionNote?: string;
}

export interface ClCompetitorRecord {
  id: ID;
  tenantId: ID;
  name: string;
  city: string | null;
  distanceMiles: number | null;
  rateIl: number | null;
  rateAl: number | null;
  rateMc: number | null;
  occupancyPct: number | null;
  notes: string | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateClCompetitorRequest {
  name: string;
  city?: string;
  distanceMiles?: number;
  rateIl?: number;
  rateAl?: number;
  rateMc?: number;
  occupancyPct?: number;
  notes?: string;
}

export interface ClLocPricingRecord {
  id: ID;
  tenantId: ID;
  level: number;
  label: string;
  description: string | null;
  addOnRate: number | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateClLocPricingRequest {
  level: number;
  label: string;
  description?: string;
  addOnRate?: number;
}

export interface ClLeakageItemRecord {
  id: ID;
  tenantId: ID;
  issue: string;
  type: string;
  monthlyImpact: number;
  status: LeakageStatus;
  resolvedBy: ID | null;
  resolvedAt: ISODateString | null;
  notes: string | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateClLeakageItemRequest {
  issue: string;
  type: string;
  monthlyImpact?: number;
  status?: LeakageStatus;
  notes?: string;
}
