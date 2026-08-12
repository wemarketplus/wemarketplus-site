import type { ID, ISODateString, PaginationParams, Prospect, ProspectStatus, Urgency } from '@/shared/types';
import type { NewProspectFormValues } from '../schema/prospectSchema';

export type { Prospect };

export type ProspectField = keyof Prospect;

// Backend stage/urgency enums — wemarketplus-backend/src/prospects/prospects.constants.ts.
// `prospects` IS the Pipeline entity: pipelineType switches which stage set applies.
// Legacy stages are retained so pre-pipeline rows stay renderable.
export const ProspectStage = {
  // legacy (pre-pipeline)
  Inquiry: 'inquiry',
  Contacted: 'contacted',
  Pending: 'pending',
  Evaluation: 'evaluation',
  Inactive: 'inactive',
  // referral-to-admit
  NewReferral: 'new_referral',
  Eligibility: 'eligibility',
  FaceToFace: 'face_to_face',
  ConsentOrder: 'consent_order',
  Admitted: 'admitted',
  // outreach
  Identified: 'identified',
  FirstVisit: 'first_visit',
  InService: 'in_service',
  Active: 'active',
  Champion: 'champion',
  // shared terminal
  Lost: 'lost',
} as const;
export type ProspectStage = (typeof ProspectStage)[keyof typeof ProspectStage];

export const ProspectPipelineType = {
  ReferralToAdmit: 'referral_to_admit',
  Outreach: 'outreach',
} as const;
export type ProspectPipelineType =
  (typeof ProspectPipelineType)[keyof typeof ProspectPipelineType];

export const PipelineStatus = {
  Open: 'open',
  WonAdmitted: 'won_admitted',
  Lost: 'lost',
} as const;
export type PipelineStatus = (typeof PipelineStatus)[keyof typeof PipelineStatus];

export const ProspectLostReason = {
  NotEligible: 'not_eligible',
  ChoseCompetitor: 'chose_competitor',
  Declined: 'declined',
  Deceased: 'deceased',
  Other: 'other',
} as const;
export type ProspectLostReason =
  (typeof ProspectLostReason)[keyof typeof ProspectLostReason];

export const ProspectLevelOfCare = {
  Routine: 'routine',
  Continuous: 'continuous',
  Inpatient: 'inpatient',
  Respite: 'respite',
} as const;
export type ProspectLevelOfCare =
  (typeof ProspectLevelOfCare)[keyof typeof ProspectLevelOfCare];

export const ProspectPayer = {
  Medicare: 'medicare',
  Medicaid: 'medicaid',
  Private: 'private',
  Other: 'other',
} as const;
export type ProspectPayer = (typeof ProspectPayer)[keyof typeof ProspectPayer];

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
  patientDob: string | null;
  pipelineName: string | null;
  pipelineType: ProspectPipelineType;
  stageEnteredAt: ISODateString | null;
  status: PipelineStatus;
  lostReason: ProspectLostReason | null;
  closedAt: ISODateString | null;
  levelOfCare: ProspectLevelOfCare | null;
  payer: ProspectPayer | null;
  expectedAdmitDate: string | null;
  primaryContactId: ID | null;
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
  patientDob?: string;
  pipelineName?: string;
  pipelineType?: ProspectPipelineType;
  status?: PipelineStatus;
  lostReason?: ProspectLostReason;
  levelOfCare?: ProspectLevelOfCare;
  payer?: ProspectPayer;
  expectedAdmitDate?: string;
  primaryContactId?: string;
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
  pipelineType?: ProspectPipelineType;
  status?: PipelineStatus;
  assignedTo?: string;
  referralSourceId?: string;
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

/**
 * One row of the re-engagement queue: the prospect plus WHY it is listed.
 * Mirrors the backend ReengagementRowDto.
 */
export interface ReengagementRow {
  prospect: ProspectRecord;
  lastActivityAt: ISODateString;
  daysInactive: number;
}

/**
 * One patient in the directory — mirrors the backend MyPatientResponseDto, which is
 * deliberately NOT a pipeline row: id, name and stage, with none of the PHI a
 * `ProspectRecord` carries. This is what the clinical roles are allowed to read, so
 * never widen it into `ProspectRecord` at a call site.
 */
export interface PatientDirectoryEntry {
  id: ID;
  patientName: string;
  stage: string;
}

/**
 * Read-only context about one patient — mirrors the backend
 * PatientContextResponseDto. Names only: who referred them and the contact on that
 * referral, with none of the account data (volume, scorecard, phone, email) the
 * referral-source and contact records carry.
 */
export interface PatientContextRecord {
  id: ID;
  patientName: string;
  referralSourceName: string | null;
  primaryContactName: string | null;
  /** Raw enum value, e.g. `discharge_planner`. */
  primaryContactRole: string | null;
}
