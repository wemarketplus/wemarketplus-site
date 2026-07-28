import type { ID, ISODateString, PaginationParams } from '@/shared/types';
import type { ProspectRecord } from '@/modules/prospects/types/prospectsTypes';

// Backend enums — wemarketplus-backend/src/leads/leads.constants.ts.
export const LeadSourceType = {
  Fax: 'fax',
  WebForm: 'web_form',
  Phone: 'phone',
  Email: 'email',
  SpreadsheetImport: 'spreadsheet_import',
  WalkIn: 'walk_in',
} as const;
export type LeadSourceType = (typeof LeadSourceType)[keyof typeof LeadSourceType];

export const LeadStatus = {
  New: 'new',
  Reviewing: 'reviewing',
  Converted: 'converted',
  Disqualified: 'disqualified',
} as const;
export type LeadStatus = (typeof LeadStatus)[keyof typeof LeadStatus];

export const LeadDisqualifyReason = {
  NotEligible: 'not_eligible',
  Duplicate: 'duplicate',
  WrongServiceArea: 'wrong_service_area',
  BadData: 'bad_data',
} as const;
export type LeadDisqualifyReason =
  (typeof LeadDisqualifyReason)[keyof typeof LeadDisqualifyReason];

// Mirrors wemarketplus-backend/src/leads/dto/lead-response.dto.ts.
export interface LeadRecord {
  id: ID;
  tenantId: ID;
  sourceType: LeadSourceType;
  sourceDetail: string | null;
  receivedAt: ISODateString;
  status: LeadStatus;
  patientName: string | null;
  patientDob: string | null;
  diagnosisReason: string | null;
  referringPerson: string | null;
  referringOrg: string | null;
  assignedTo: ID | null;
  disqualifyReason: LeadDisqualifyReason | null;
  convertedContactId: ID | null;
  convertedCompanyId: ID | null;
  convertedPipelineId: ID | null;
  convertedAt: ISODateString | null;
  createdBy: ID | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

// POST /hl/leads body.
export interface CreateLeadRequest {
  sourceType?: LeadSourceType;
  sourceDetail?: string;
  receivedAt?: string;
  patientName?: string;
  patientDob?: string;
  diagnosisReason?: string;
  referringPerson?: string;
  referringOrg?: string;
  assignedTo?: string;
}

// PATCH /hl/leads/:id — only the pre-conversion statuses are settable here;
// converted/disqualified are reached through their dedicated endpoints.
export type UpdateLeadRequest = Partial<CreateLeadRequest> & {
  status?: typeof LeadStatus.New | typeof LeadStatus.Reviewing;
};

// GET /hl/leads query.
export interface ListLeadsQuery extends PaginationParams {
  search?: string;
  status?: LeadStatus;
  sourceType?: LeadSourceType;
  assignedTo?: string;
}

// POST /hl/leads/:id/convert body — every field optional; the backend derives the
// account and contact from the lead when not supplied.
export interface ConvertLeadRequest {
  companyId?: string;
  contactId?: string;
  companyType?: string;
  assignedTo?: string;
  levelOfCare?: string;
  payer?: string;
}

// POST /hl/leads/:id/convert response.
export interface LeadConversionResult {
  lead: LeadRecord;
  pipeline: ProspectRecord;
  companyId: ID | null;
  contactId: ID | null;
}

export interface DisqualifyLeadRequest {
  disqualifyReason: LeadDisqualifyReason;
}

export interface LeadsUiState {
  search: string;
  statusFilter: LeadStatus | 'all';
  sourceFilter: LeadSourceType | 'all';
}
