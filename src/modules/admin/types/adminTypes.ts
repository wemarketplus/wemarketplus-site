import type { ID, ISODateString } from '@/shared/types';
import { Product } from '@/shared/types';

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
  /**
   * The product this dataset belongs to, or undefined for cross-product ones.
   *
   * The import/export hub is a SHARED screen reached from both dashboards, so a
   * HospiceLink-only dataset like `prospects` must not appear for a
   * CommunityLink tenant — they have no such records, and offering the import
   * would only produce an empty file or a confusing error.
   */
  product?: Product;
}

export const DATASET_OPTIONS: readonly DatasetOption[] = [
  { type: 'companies', label: 'Companies', canImport: true, elevated: false },
  { type: 'locations', label: 'Locations', canImport: true, elevated: false },
  // DEPRECATED — NOT NEEDED, PENDING REMOVAL. The `funding` and `applications`
  // datasets are Grants-domain; the domain was hidden from the UI on 2026-08-06
  // per the product owner, so they are no longer offered for import/export. The
  // backend registry still declares them (dataset-registry.ts) — this only
  // removes them from the picker. Re-list them here to restore.
  // { type: 'funding', label: 'Funding opportunities', canImport: true, elevated: false },
  // { type: 'applications', label: 'Applications', canImport: true, elevated: false },
  { type: 'revenue', label: 'Revenue', canImport: false, elevated: false },
  { type: 'users', label: 'Users', canImport: false, elevated: true },
  { type: 'audit', label: 'Audit log', canImport: false, elevated: true },
  // HospiceLink patient pipeline. The Admin / Office Manager bulk-onboarding
  // path: an agency arriving from another CRM lands its book of business here.
  //
  // `elevated` because the export half carries PHI (patient name, DOB,
  // diagnosis) — the backend puts `prospects` in ELEVATED_EXPORT_TYPES for the
  // same reason.
  {
    type: 'prospects',
    label: 'Prospects',
    canImport: true,
    elevated: true,
    product: Product.HospiceLink,
  },
];

/**
 * Datasets offered for the dashboard currently in use.
 *
 * A dataset with no `product` is cross-product and always offered.
 */
export const datasetOptionsForProduct = (
  product: Product | null,
): readonly DatasetOption[] =>
  DATASET_OPTIONS.filter(
    (option) => option.product === undefined || option.product === product,
  );
