import type { ID, ISODateString, PaginationParams } from '@/shared/types';
import type { CompanyStatus } from '../constants/companiesConstants';

// Mirrors wemarketplus-backend/src/companies/dto/company-response.dto.ts.
export interface CompanyRecord {
  id: ID;
  tenantId: ID;
  companyName: string;
  companyType: string | null;
  status: CompanyStatus;
  fein: string | null;
  industry: string | null;
  naicsCode: string | null;
  domain: string | null;
  website: string | null;
  employeeCountTotal: number | null;
  employeeCountFt: number | null;
  employeeCountPt: number | null;
  avgHourlyWage: number | null;
  primaryContactName: string | null;
  primaryContactEmail: string | null;
  primaryContactPhone: string | null;
  trainingNeeds: string | null;
  notes: string | null;
  rating: number | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateCompanyRequest {
  companyName: string;
  companyType?: string;
  status?: CompanyStatus;
  fein?: string;
  industry?: string;
  naicsCode?: string;
  domain?: string;
  website?: string;
  employeeCountTotal?: number;
  primaryContactName?: string;
  primaryContactEmail?: string;
  primaryContactPhone?: string;
  trainingNeeds?: string;
  notes?: string;
}

export type UpdateCompanyRequest = Partial<CreateCompanyRequest>;

export interface ListCompaniesQuery extends PaginationParams {
  status?: CompanyStatus;
  search?: string;
}

/** One set of records that normalise to the same name (GET /companies/dedup/preview). */
export interface CompanyDedupGroup {
  keeperName: string;
  duplicateNames: string[];
}

/**
 * What a dedup run would do, computed without mutating anything. Dedup HARD-DELETES
 * the duplicates after re-pointing their locations and applications at the keeper,
 * so the confirmation dialog shows this first.
 */
export interface CompanyDedupPreview {
  totalGroups: number;
  wouldDelete: number;
  groups: CompanyDedupGroup[];
}

/**
 * Outcome of POST /companies/dedup.
 *
 * `merged` and `deleted` are NOT the same number and neither is "how many
 * duplicates were resolved":
 *   - `deleted`  = duplicate rows permanently removed. This is what the user asked
 *                  for and what the confirmation promised, so it is what we report.
 *   - `merged`   = keeper rows that received a field patch, because the duplicate
 *                  carried a value the keeper was missing. Often 0 even on a
 *                  successful merge — the reason the toast used to read
 *                  "Merged 0 duplicate companies" right after deleting one.
 *   - `totalGroups` = duplicate sets processed.
 */
export interface CompanyDedupResult {
  merged: number;
  deleted: number;
  errors: string[];
  totalGroups: number;
  complete: boolean;
}
