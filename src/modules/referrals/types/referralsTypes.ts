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
  notes?: string;
  aiScore?: number;
}

export type UpdateReferralSourceRequest = Partial<CreateReferralSourceRequest>;

export type ListReferralSourcesQuery = PaginationParams;

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
