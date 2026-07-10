import { opt, optNum } from '@/shared/ui/entity';
import type {
  CompanyRecord,
  CreateCompanyRequest,
  UpdateCompanyRequest,
} from '../types/companiesTypes';
import type { CompanyStatus } from '../constants/companiesConstants';
import type { CompanyFormValues } from '../schema/companySchema';

// Form values -> POST /companies body. Drops blank optionals so we never send
// empty strings the DTO rejects (website/email are IsUrl/IsEmail gated).
export function toCreateCompany(values: CompanyFormValues): CreateCompanyRequest {
  return {
    companyName: values.companyName.trim(),
    ...(values.status ? { status: values.status as CompanyStatus } : {}),
    ...opt('companyType', values.companyType),
    ...opt('industry', values.industry),
    ...opt('naicsCode', values.naicsCode),
    ...opt('fein', values.fein),
    ...optNum('employeeCountTotal', values.employeeCountTotal),
    ...opt('domain', values.domain),
    ...opt('website', values.website),
    ...opt('primaryContactName', values.primaryContactName),
    ...opt('primaryContactEmail', values.primaryContactEmail),
    ...opt('primaryContactPhone', values.primaryContactPhone),
    ...opt('trainingNeeds', values.trainingNeeds),
    ...opt('notes', values.notes),
  };
}

export function toUpdateCompany(values: CompanyFormValues): UpdateCompanyRequest {
  return toCreateCompany(values);
}

// Seeds the edit form from an existing record (nulls -> '').
export function toCompanyFormValues(company: CompanyRecord): CompanyFormValues {
  return {
    companyName: company.companyName,
    status: company.status,
    companyType: company.companyType ?? '',
    industry: company.industry ?? '',
    naicsCode: company.naicsCode ?? '',
    fein: company.fein ?? '',
    employeeCountTotal: company.employeeCountTotal ?? undefined,
    domain: company.domain ?? '',
    website: company.website ?? '',
    primaryContactName: company.primaryContactName ?? '',
    primaryContactEmail: company.primaryContactEmail ?? '',
    primaryContactPhone: company.primaryContactPhone ?? '',
    trainingNeeds: company.trainingNeeds ?? '',
    notes: company.notes ?? '',
  };
}
