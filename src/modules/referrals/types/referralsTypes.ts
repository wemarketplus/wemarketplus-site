import type { ID, ISODateString, PaginationParams, ReferralSourceStatus } from '@/shared/types';
import type { NewReferralFormValues } from '../schema/referralSchema';

// Backend type enum — wemarketplus-backend/src/referral-sources/referral-sources.constants.ts.
export const ReferralSourceType = {
  Hospital: 'hospital',
  SkilledNursing: 'skilled_nursing',
  AssistedLiving: 'assisted_living',
  Physician: 'physician',
  HomeHealth: 'home_health',
  Icu: 'icu',
  MemoryCare: 'memory_care',
  Facility: 'facility',
  Other: 'other',
} as const;
export type ReferralSourceType = (typeof ReferralSourceType)[keyof typeof ReferralSourceType];

// Account priority tier + lifecycle status — the referral_sources table is the
// HospiceLink "Company"/account record (facility, SNF, ALF, physician group).
export const ReferralSourcePriorityTier = {
  A: 'A',
  B: 'B',
  C: 'C',
} as const;
export type ReferralSourcePriorityTier =
  (typeof ReferralSourcePriorityTier)[keyof typeof ReferralSourcePriorityTier];

export const ReferralAccountStatus = {
  Prospect: 'prospect',
  ActiveReferrer: 'active_referrer',
  Dormant: 'dormant',
} as const;
export type ReferralAccountStatus =
  (typeof ReferralAccountStatus)[keyof typeof ReferralAccountStatus];

// Mirrors wemarketplus-backend/src/referral-sources/dto/referral-source-response.dto.ts.
export interface ReferralSourceRecord {
  id: ID;
  tenantId: ID;
  name: string;
  type: ReferralSourceType;
  contactName: string | null;
  phone: string | null;
  email: string | null;
  address: string | null;
  city: string | null;
  state: string | null;
  zip: string | null;
  fax: string | null;
  website: string | null;
  parentCompanyId: ID | null;
  territoryId: ID | null;
  priorityTier: ReferralSourcePriorityTier;
  status: ReferralAccountStatus;
  referralVolume: number;
  accountOwnerId: ID | null;
  notes: string | null;
  aiScore: number;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

// POST /referral-sources body.
export interface CreateReferralSourceRequest {
  name: string;
  type?: ReferralSourceType;
  contactName?: string;
  phone?: string;
  email?: string;
  address?: string;
  city?: string;
  state?: string;
  zip?: string;
  fax?: string;
  website?: string;
  parentCompanyId?: string;
  territoryId?: string;
  priorityTier?: ReferralSourcePriorityTier;
  status?: ReferralAccountStatus;
  referralVolume?: number;
  accountOwnerId?: string;
  notes?: string;
  aiScore?: number;
}

export type UpdateReferralSourceRequest = Partial<CreateReferralSourceRequest>;

// GET /referral-sources query — server-side search + equality filters.
export interface ListReferralSourcesQuery extends PaginationParams {
  search?: string;
  type?: ReferralSourceType;
  status?: ReferralAccountStatus;
  priorityTier?: ReferralSourcePriorityTier;
  territoryId?: string;
  accountOwnerId?: string;
  parentCompanyId?: string;
}

export interface ReferralsUiState {
  search: string;
  statusFilter: ReferralSourceStatus | 'all';
}

export interface ReferralFilterChip {
  value: ReferralSourceStatus | 'all';
  label: string;
}

// --- Component prop types ---

export interface AddReferralModalProps {
  open: boolean;
  isSaving: boolean;
  onClose: () => void;
  // Returns true when the create succeeded, so the form can reset.
  onSubmit: (values: NewReferralFormValues) => Promise<boolean>;
}
