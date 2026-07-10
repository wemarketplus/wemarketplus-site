import type { ID, ISODateString } from '@/shared/types';

// Mirrors wemarketplus-backend TenantResponseDto. The settings Organization tab
// only edits the profile subset (name, city, state, phone) via PATCH /tenants/me;
// subscription/tier fields are read-only here and driven by the billing pipeline.
export interface TenantProfile {
  id: ID;
  name: string;
  city: string | null;
  state: string | null;
  phone: string | null;
  product: string;
  crmTier: string;
  package: string;
  subscriptionStatus: string;
  isActive: boolean;
  baaSigned: boolean;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

// Body accepted by PATCH /tenants/me (backend UpdateMyTenantDto). Profile fields
// only — anything else is rejected by the backend's forbidNonWhitelisted pipe.
export interface UpdateMyTenantRequest {
  name?: string;
  city?: string;
  state?: string;
  phone?: string;
}
