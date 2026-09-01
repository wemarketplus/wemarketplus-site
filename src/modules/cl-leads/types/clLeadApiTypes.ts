import type { ID, ISODateString } from '@/shared/types';
import type {
  ClCareLevel,
  ClLeadStage,
  ClLostReason,
  ClResidentNoteCategory,
  ClUrgency,
} from '../constants/clLeadApiConstants';

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
  /** Set only while the lead sits in `lost`; the server clears it on revival. */
  lostReason: ClLostReason | null;
  lostReasonDetail: string | null;
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
  /**
   * `null` as well as `undefined`, deliberately. Omitting a key means "leave it
   * alone", so without null a mistaken reason could never be cleared — and the
   * server sends null itself when a lead moves off `lost`.
   */
  lostReason?: ClLostReason | null;
  lostReasonDetail?: string | null;
}

export type UpdateClLeadRequest = Partial<CreateClLeadRequest>;

export interface ClLeadNoteRecord {
  id: ID;
  tenantId: ID;
  /** Null for an Activity Note — a general note with no lead as its subject. */
  leadId: ID | null;
  /** Set for a Resident Care Log entry — a note whose subject is a resident. */
  residentId: ID | null;
  summary: string;
  contactType: string | null;
  nextStep: string | null;
  followUpDate: string | null;
  gpsLocation: string | null;
  /** Null for every note that is not a Resident Care Log entry. */
  category: ClResidentNoteCategory | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateClLeadNoteRequest {
  /** Omit for a general Activity Note. */
  leadId?: string;
  /** Set to log this note as a Resident Care Log entry. */
  residentId?: string;
  summary: string;
  contactType?: string;
  nextStep?: string;
  followUpDate?: string;
  category?: ClResidentNoteCategory;
}

// Backend record shape for a CommunityLink resident (`cl_residents`) — the
// Resident Care Log's subject. See wemarketplus-backend's ClResident entity for
// the "one active resident per apartment, closed not deleted" model this mirrors.
export interface ClResidentRecord {
  id: ID;
  tenantId: ID;
  apartmentId: ID;
  firstName: string;
  lastName: string;
  dateOfBirth: string | null;
  moveInDate: string | null;
  /** Null means this resident is still active (has not moved out). */
  moveOutDate: string | null;
  careLevel: ClCareLevel;
  emergencyContactName: string | null;
  emergencyContactPhone: string | null;
  notes: string | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateClResidentRequest {
  apartmentId: string;
  firstName: string;
  lastName: string;
  dateOfBirth?: string;
  moveInDate?: string;
  moveOutDate?: string;
  careLevel?: ClCareLevel;
  emergencyContactName?: string;
  emergencyContactPhone?: string;
  notes?: string;
}
