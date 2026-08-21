import { useMemo } from 'react';
import { useListApplicationsQuery } from '@/modules/applications/api/applicationsApi';
import { useListCompaniesQuery } from '@/modules/companies/api/companiesApi';
import { useListFundingQuery } from '@/modules/funding/api/fundingApi';
import { STAGE_LABELS } from '@/modules/prospects/constants/prospectsConstants';
import { useListProspectsQuery } from '@/modules/prospects/api/prospectsApi';
import { useListReferralsQuery } from '@/modules/referrals/api/referralsApi';
import { useListUsersQuery } from '@/modules/users/api/usersApi';
import { fullName } from '@/modules/users/utils/userDisplay';
import type { EntitySelectOption } from '@/shared/ui/entity';
import {
  LOOKUP_PAGE_SIZE,
  useLookupOptions,
  useNameTable,
  type NameTable,
} from './useRecordLookups';

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

/**
 * Employer companies as NAME-valued options, for the referral-intake org fields.
 *
 * `useCompanyLookup` above is the picker for a foreign key: it writes a company
 * id, because the column it fills stores one. This one is NOT that. `leads.referringOrg`
 * is a plain text column that the list view and the search filter read verbatim,
 * so the picker has to write the company NAME the column already holds — writing
 * an id there would put a raw uuid on screen and break the search.
 *
 * Same list, same tenant scope, different value. Options come from whatever the
 * Companies tab holds, so adding a company there is what adds a choice here.
 *
 * Names are deduped and blanks dropped: `companyName` is not unique (dedup is a
 * manual admin action, not a DB constraint) and a <select> cannot carry two
 * options with the same value.
 */
export function useCompanyNameOptions(enabled: boolean): Options {
  const { data, isLoading } = useListCompaniesQuery(PAGE, { skip: !enabled });
  const rows = data?.data;
  return useMemo(() => {
    // Mirrors useLookupOptions: only "loading" yields undefined, so a settled
    // empty list reads as "nothing to choose" instead of hanging on "Loading…".
    if (isLoading) return undefined;
    const names = [
      ...new Set((rows ?? []).map((c) => c.companyName.trim()).filter(Boolean)),
    ];
    return names
      .sort((a, b) => a.localeCompare(b))
      .map((name) => ({ value: name, label: name }));
  }, [rows, isLoading]);
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

/**
 * Referral sources (facilities/accounts), for REVENUE ATTRIBUTION.
 *
 * The write-side counterpart to `useReferralSourceNames` below, and the reason
 * Revenue Intelligence had nothing to report: `invoices.referralSourceId` and the
 * matching column on contracts existed, and the Intelligence queries aggregated on
 * them, but no form in the product could set one — so every invoice raised through
 * the UI carried a null source and "revenue by referral source" was permanently
 * empty. The chain from an admission to its money is only closed when a human can
 * pick the account here.
 */
export function useReferralSourceLookup(enabled: boolean): Options {
  const { data, isLoading } = useListReferralsQuery(PAGE, { skip: !enabled });
  return useLookupOptions(data?.data, isLoading, (r) => r.name);
}

/**
 * Admitted/pipeline prospects, for the other half of the same attribution pair.
 *
 * Labelled by `patientName` with the stage appended, because a hospice tenant will
 * hold the same family name more than once and the stage is what tells two apart.
 */
export function useProspectLookup(enabled: boolean): Options {
  const { data, isLoading } = useListProspectsQuery(PAGE, { skip: !enabled });
  return useLookupOptions(
    data?.data,
    isLoading,
    (p) => `${p.patientName} — ${STAGE_LABELS[p.stage] ?? p.stage}`,
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

// --- Display-side name tables ------------------------------------------------
// The pickers above WRITE a reference; these READ one back, so a list view can
// show a name where the row only stores an id. Unlike the pickers these are not
// gated on a modal being open — a table needs them on first paint — and they
// resolve through `displayName()`, which yields '' rather than the id.

/** Tenant users, for rendering a stored `createdBy` / `assignedTo`. */
export function useUserNames(): NameTable {
  const { data } = useListUsersQuery(PAGE);
  return useNameTable(data?.data, (u) => fullName(u) || u.email);
}

/** Referral sources, for rendering a stored `referralSourceId`. */
export function useReferralSourceNames(): NameTable {
  const { data } = useListReferralsQuery(PAGE);
  return useNameTable(data?.data, (r) => r.name);
}
