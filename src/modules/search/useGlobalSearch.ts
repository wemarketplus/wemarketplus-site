import { useMemo } from 'react';
import { Building2, Contact, UserSearch } from 'lucide-react';
import { useDebounce } from '@/shared/hooks';
import { useListContactsQuery } from '@/modules/contacts';
import { useListCompaniesQuery } from '@/modules/companies';
import { useListProspectsQuery } from '@/modules/prospects';
import type { SearchGroup, SearchResult } from './types';

// Max results shown per entity group — keeps the palette scannable and the
// queries small.
const PER_GROUP_CAP = 5;
// Min characters before we hit the network. Below this, all queries are skipped.
const MIN_QUERY = 2;

// Client-side federated search across the entities that already expose list
// queries. There is no backend global-search endpoint, so we fan out to the
// existing RTK Query list hooks (debounced) and merge the results grouped by
// entity. Companies accept a server-side `search` param; contacts and prospects
// do not, so we fetch a page and filter it client-side. RTK Query caches +
// dedupes, and `skip` cancels the queries when the palette is closed or the
// query is too short, so stale requests never land.
export function useGlobalSearch(rawQuery: string, enabled: boolean) {
  const query = useDebounce(rawQuery.trim(), 200);
  const active = enabled && query.length >= MIN_QUERY;
  const needle = query.toLowerCase();

  const contacts = useListContactsQuery(
    { page: 1, limit: 25 },
    { skip: !active },
  );
  const companies = useListCompaniesQuery(
    { page: 1, limit: PER_GROUP_CAP, search: query },
    { skip: !active },
  );
  // Prospects have no server-side search param — fetch a page and filter below.
  const prospects = useListProspectsQuery(
    { page: 1, limit: 25 },
    { skip: !active },
  );

  const groups = useMemo<SearchGroup[]>(() => {
    // Contacts have no server-side search — filter the fetched page ourselves.
    const contactResults: SearchResult[] = (contacts.data?.data ?? [])
      .filter(
        (c) =>
          c.name.toLowerCase().includes(needle) ||
          (c.email?.toLowerCase().includes(needle) ?? false) ||
          (c.title?.toLowerCase().includes(needle) ?? false),
      )
      .slice(0, PER_GROUP_CAP)
      .map((c) => ({
        id: c.id,
        group: 'contacts' as const,
        title: c.name,
        subtitle: c.email ?? c.title ?? undefined,
        to: '/contacts',
      }));

    const companyResults: SearchResult[] = (companies.data?.data ?? [])
      .slice(0, PER_GROUP_CAP)
      .map((c) => ({
        id: c.id,
        group: 'companies' as const,
        title: c.companyName,
        subtitle: c.industry ?? c.primaryContactName ?? undefined,
        to: '/companies',
      }));

    const prospectResults: SearchResult[] = (prospects.data?.data ?? [])
      .filter(
        (p) =>
          p.patientName.toLowerCase().includes(needle) ||
          (p.facilityName?.toLowerCase().includes(needle) ?? false) ||
          (p.city?.toLowerCase().includes(needle) ?? false),
      )
      .slice(0, PER_GROUP_CAP)
      .map((p) => ({
        id: p.id,
        group: 'prospects' as const,
        title: p.patientName,
        subtitle: p.facilityName ?? p.city ?? undefined,
        to: '/prospects',
      }));

    return [
      {
        key: 'contacts',
        label: 'Contacts',
        icon: Contact,
        results: contactResults,
        isLoading: contacts.isFetching,
      },
      {
        key: 'companies',
        label: 'Companies',
        icon: Building2,
        results: companyResults,
        isLoading: companies.isFetching,
      },
      {
        key: 'prospects',
        label: 'Prospects',
        icon: UserSearch,
        results: prospectResults,
        isLoading: prospects.isFetching,
      },
    ];
  }, [
    needle,
    contacts.data,
    contacts.isFetching,
    companies.data,
    companies.isFetching,
    prospects.data,
    prospects.isFetching,
  ]);

  // Flat, ordered list for keyboard navigation (contacts, then companies, …).
  const flat = useMemo(() => groups.flatMap((g) => g.results), [groups]);

  const isLoading = active && (contacts.isFetching || companies.isFetching || prospects.isFetching);
  const hasResults = flat.length > 0;

  return {
    query,
    active,
    minQuery: MIN_QUERY,
    groups,
    flat,
    isLoading,
    hasResults,
  };
}
