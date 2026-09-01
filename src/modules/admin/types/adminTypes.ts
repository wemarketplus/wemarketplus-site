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
  // HospiceLink referral intake. The backend registry has always declared this
  // dataset; it was simply never listed here, so the one thing "HospiceLink
  // already has bulk lead import" was taken to mean was not actually reachable
  // through the UI. Elevated to match — an inbound lead carries patient name, DOB
  // and diagnosis, and the backend puts `leads` in ELEVATED_EXPORT_TYPES.
  {
    type: 'leads',
    label: 'Inbound leads',
    canImport: true,
    elevated: true,
    product: Product.HospiceLink,
  },
  // CommunityLink lead pipeline — the one-at-a-time Add Lead gap.
  //
  // NOT elevated, unlike its two HospiceLink neighbours above: a CommunityLink
  // lead is a prospective resident enquiry with contact details and a budget. No
  // diagnosis, no date of birth, no patient. Gating a sales list as if it were PHI
  // would be a permission barrier with nothing behind it.
  {
    type: 'cl-leads',
    label: 'Leads',
    canImport: true,
    elevated: false,
    product: Product.CommunityLink,
  },
  // CommunityLink occupancy. Units themselves are created one-at-a-time during
  // community/property setup; this only bulk-loads resident occupancy onto units
  // that already exist, matched by unit number — see `upsertKey` on
  // DatasetDescriptor in the backend registry. A sheet naming a unit number
  // nobody set up yet is reported as an error, not created as a new unit.
  //
  // NOT elevated, matching cl-leads: a resident name and care level is not PHI
  // the way a diagnosis or date of birth is.
  {
    type: 'cl-apartments',
    label: 'Apartments/Units',
    canImport: true,
    elevated: false,
    product: Product.CommunityLink,
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
