import type { ID, ISODateString } from '@/shared/types';

// Platform admin — wemarketplus-backend tenants, invites (admin/owner only).
export interface TenantRecord {
  id: ID;
  name: string;
  city: string | null;
  state: string | null;
  phone: string | null;
  product: string;
  crmTier: string;
  subscriptionStatus: string;
  isActive: boolean;
}

export interface CreateTenantRequest {
  name: string;
  city?: string;
  state?: string;
  phone?: string;
  product?: string;
  crmTier?: string;
}

export interface InviteRecord {
  id: ID;
  tenantId: ID;
  userId: ID;
  expiresAt: ISODateString;
  acceptedAt: ISODateString | null;
  createdAt: ISODateString;
}

export interface ImportDataRequest {
  type: string;
  rows: Record<string, unknown>[];
  batch?: number;
  totalBatches?: number;
}
