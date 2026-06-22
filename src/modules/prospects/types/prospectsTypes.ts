import type { ID, ISODateString, PaginationParams, Prospect, ProspectStatus, Urgency } from '@/shared/types';
import type { NewProspectFormValues } from '../schema/prospectSchema';

export type { Prospect };

export type ProspectField = keyof Prospect;

// Backend stage/urgency enums — wemarketplus-backend/src/prospects/prospects.constants.ts.
export const ProspectStage = {
  Inquiry: 'inquiry',
  Contacted: 'contacted',
  Pending: 'pending',
  Evaluation: 'evaluation',
  Admitted: 'admitted',
  Lost: 'lost',
  Inactive: 'inactive',
} as const;
export type ProspectStage = (typeof ProspectStage)[keyof typeof ProspectStage];

export const ProspectUrgency = {
  Hot: 'hot',
  Warm: 'warm',
  Cold: 'cold',
} as const;
export type ProspectUrgency = (typeof ProspectUrgency)[keyof typeof ProspectUrgency];

// Mirrors wemarketplus-backend/src/prospects/dto/prospect-response.dto.ts.
export interface ProspectRecord {
  id: ID;
  tenantId: ID;
  patientName: string;
  facilityName: string | null;
  stage: ProspectStage;
  urgency: ProspectUrgency;
  isHotLead: boolean;
  referringPhysician: string | null;
  referralSourceId: ID | null;
  diagnosis: string | null;
  address: string | null;
  city: string | null;
  state: string | null;
  zip: string | null;
  phone: string | null;
  emergencyContact: string | null;
  notes: string | null;
  assignedTo: ID | null;
  aiAdmitScore: number | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

// POST /prospects body — wemarketplus-backend/src/prospects/dto/create-prospect.dto.ts.
export interface CreateProspectRequest {
  patientName: string;
  facilityName?: string;
  stage?: ProspectStage;
  urgency?: ProspectUrgency;
  isHotLead?: boolean;
  referringPhysician?: string;
  referralSourceId?: string;
  diagnosis?: string;
  address?: string;
  city?: string;
  state?: string;
  zip?: string;
  phone?: string;
  emergencyContact?: string;
  notes?: string;
  assignedTo?: string;
}

// PATCH /prospects/:id body — all fields optional.
export type UpdateProspectRequest = Partial<CreateProspectRequest>;

// GET /prospects query.
export interface ListProspectsQuery extends PaginationParams {
  stage?: ProspectStage;
  assignedTo?: string;
}

export interface ProspectsUiState {
  search: string;
  statusFilter: ProspectStatus | 'all';
  urgencyFilter: Urgency | 'all';
}

// --- Component prop types ---

export interface AddProspectModalProps {
  open: boolean;
  isSaving: boolean;
  onClose: () => void;
  // Returns true when the create succeeded, so the form can reset.
  onSubmit: (values: NewProspectFormValues) => Promise<boolean>;
}
