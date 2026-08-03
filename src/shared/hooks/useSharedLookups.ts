import { useListApplicationsQuery } from '@/modules/applications/api/applicationsApi';
import { useListCompaniesQuery } from '@/modules/companies/api/companiesApi';
import { useListFundingQuery } from '@/modules/funding/api/fundingApi';
import { useListUsersQuery } from '@/modules/users/api/usersApi';
import type { EntitySelectOption } from '@/shared/ui/entity';
import { LOOKUP_PAGE_SIZE, useLookupOptions } from './useRecordLookups';

/**
 * The record pickers shared by the back-office forms (Applications, Invoices,
 * Funding, Locations, Territories).
 *
 * Every one of these used to be a text box labelled "… id (UUID)". There is no
 * screen anywhere in this app that shows a user a UUID, so those fields could only
 * be filled by someone reading the database — which means in practice they were
 * left blank and the links were never made. Each hook below is scoped to the one
 * lookup a form needs, so a form never fetches lists it does not use.
 *
 * `enabled` is the owning modal's open state.
 */
const PAGE = { page: 1, limit: LOOKUP_PAGE_SIZE } as const;

type Options = readonly EntitySelectOption[] | undefined;

/** Employer companies (Grants side). */
export function useCompanyLookup(enabled: boolean): Options {
  const { data, isLoading } = useListCompaniesQuery(PAGE, { skip: !enabled });
  return useLookupOptions(data?.data, isLoading, (c) => c.companyName);
}

/** Funding opportunities. */
export function useFundingLookup(enabled: boolean): Options {
  const { data, isLoading } = useListFundingQuery(PAGE, { skip: !enabled });
  return useLookupOptions(data?.data, isLoading, (f) => f.opportunityName);
}

/**
 * Grant applications. `applicationNumber` is nullable, so fall back to a short id
 * fragment rather than rendering a blank option a user cannot tell apart.
 */
export function useApplicationLookup(enabled: boolean): Options {
  const { data, isLoading } = useListApplicationsQuery(PAGE, { skip: !enabled });
  return useLookupOptions(
    data?.data,
    isLoading,
    (a) => a.applicationNumber?.trim() || `Application ${a.id.slice(0, 8)}`,
  );
}

/** Tenant users, for "assigned to" style fields. */
export function useUserLookup(enabled: boolean): Options {
  const { data, isLoading } = useListUsersQuery(PAGE, { skip: !enabled });
  return useLookupOptions(data?.data, isLoading, (u) => {
    const name = [u.firstName, u.lastName].filter(Boolean).join(' ').trim();
    return name ? `${name} — ${u.email}` : u.email;
  });
}
