import type { ID, ISODateString } from '@/shared/types';
import type { ClCareLevel, ClLeadStage, ClUrgency } from '../constants/clLeadApiConstants';

// Backend record shapes for CommunityLink leads + lead-notes. Distinct from the
// UI-layer Lead view-model in @/shared/types (mapped in utils/leadsUtils).
export interface ClLeadRecord {
  id: ID;
  tenantId: ID;
  firstName: string;
  lastName: string | null;
  phone: string | null;
  email: string | null;
  careLevel: ClCareLevel | null;
  stage: ClLeadStage;
  urgency: ClUrgency;
  source: string | null;
  assignedTo: ID | null;
  followUpDate: string | null;
  moveInTarget: string | null;
  budgetMin: number | null;
  budgetMax: number | null;
  notes: string | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateClLeadRequest {
  firstName: string;
  lastName?: string;
  phone?: string;
  email?: string;
  careLevel?: ClCareLevel;
  stage?: ClLeadStage;
  urgency?: ClUrgency;
  source?: string;
  assignedTo?: string;
  followUpDate?: string;
  moveInTarget?: string;
  budgetMin?: number;
  budgetMax?: number;
  notes?: string;
}

export type UpdateClLeadRequest = Partial<CreateClLeadRequest>;

export interface ClLeadNoteRecord {
  id: ID;
  tenantId: ID;
  /** Null for an Activity Note — a general note with no lead as its subject. */
  leadId: ID | null;
  summary: string;
  contactType: string | null;
  nextStep: string | null;
  followUpDate: string | null;
  gpsLocation: string | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateClLeadNoteRequest {
  /** Omit for a general Activity Note. */
  leadId?: string;
  summary: string;
  contactType?: string;
  nextStep?: string;
  followUpDate?: string;
}
