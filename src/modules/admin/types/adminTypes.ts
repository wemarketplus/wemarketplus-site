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

// Result of a bulk import run — data-transfer.service ImportResult.
export interface ImportResult {
  created: number;
  errors: string[];
  batch: number;
  totalBatches: number;
}

// The data-transfer hub's dataset registry (wemarketplus-backend
// src/data-transfer/dataset-registry.ts). `canImport` mirrors which datasets
// declare templateHeaders + importRow; `elevated` marks the export-only
// datasets that require an Admin/Owner/SuperAdmin role.
export interface DatasetOption {
  type: string;
  label: string;
  canImport: boolean;
  elevated: boolean;
}

export const DATASET_OPTIONS: readonly DatasetOption[] = [
  { type: 'companies', label: 'Companies', canImport: true, elevated: false },
  { type: 'locations', label: 'Locations', canImport: true, elevated: false },
  { type: 'funding', label: 'Funding opportunities', canImport: true, elevated: false },
  { type: 'applications', label: 'Applications', canImport: true, elevated: false },
  { type: 'revenue', label: 'Revenue', canImport: false, elevated: false },
  { type: 'users', label: 'Users', canImport: false, elevated: true },
  { type: 'audit', label: 'Audit log', canImport: false, elevated: true },
];
