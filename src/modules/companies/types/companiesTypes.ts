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
