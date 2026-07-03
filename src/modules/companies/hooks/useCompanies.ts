import { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { useDebounce } from '@/shared/hooks';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import {
  usePaginatedList,
  useEntityCrud,
  useBulkSelection,
  useBulkDelete,
} from '@/shared/ui/entity';
import {
  useListCompaniesQuery,
  useCreateCompanyMutation,
  useUpdateCompanyMutation,
  useDeleteCompanyMutation,
  useDedupCompaniesMutation,
} from '../api/companiesApi';
import { COMPANIES_PAGE_SIZE } from '../constants/companiesConstants';
import { toCreateCompany, toUpdateCompany } from '../utils/companiesUtils';
import type { CompanyStatus } from '../constants/companiesConstants';
import type { CompanyFormValues } from '../schema/companySchema';
import type { CompanyRecord } from '../types/companiesTypes';

// Companies list + CRUD + dedup. Both search and status are server-side filters
// (unlike contacts, whose search is client-side). Same shape as useContacts —
// this is the second reference for the entity kit.
export function useCompanies() {
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const debouncedSearch = useDebounce(search, 250);

  const [page, setPage] = useState(1);
  // Both filters are server-side — reset to page 1 whenever either changes.
  useEffect(() => setPage(1), [debouncedSearch, status]);

  const query = useListCompaniesQuery({
    page,
    limit: COMPANIES_PAGE_SIZE,
    ...(debouncedSearch.trim() ? { search: debouncedSearch.trim() } : {}),
    ...(status ? { status: status as CompanyStatus } : {}),
  });

  const list = usePaginatedList<CompanyRecord>(query, { pageSize: COMPANIES_PAGE_SIZE });

  const [createCompany, createState] = useCreateCompanyMutation();
  const [updateCompany, updateState] = useUpdateCompanyMutation();
  const [deleteCompany, deleteState] = useDeleteCompanyMutation();
  const [dedupCompanies, dedupState] = useDedupCompaniesMutation();

  const crud = useEntityCrud<
    CompanyRecord,
    ReturnType<typeof toCreateCompany>,
    ReturnType<typeof toUpdateCompany>
  >({
    noun: 'company',
    create: createCompany,
    update: updateCompany,
    remove: deleteCompany,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (c) => c.companyName,
  });

  const submit = (values: CompanyFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateCompany(values))
      : crud.submitCreate(toCreateCompany(values));

  // Bulk (multi-select) delete — reuses deleteCompany for the sequential run.
  const selection = useBulkSelection();
  const bulkDelete = useBulkDelete({
    noun: 'company',
    nounPlural: 'companies',
    remove: deleteCompany,
  });

  const dedup = async () => {
    if (!window.confirm('Merge duplicate company records? This cannot be undone.')) return;
    try {
      const result = await dedupCompanies().unwrap();
      const merged =
        result && typeof result === 'object' && 'merged' in result
          ? (result as { merged: number }).merged
          : undefined;
      toast.success(
        typeof merged === 'number'
          ? `Merged ${merged} duplicate ${merged === 1 ? 'company' : 'companies'}`
          : 'Deduplication complete',
      );
    } catch (err) {
      toast.error(extractApiErrorMessage(err, 'Could not deduplicate companies.'));
    }
  };

  return {
    ...list,
    page,
    prevPage: () => setPage((p) => Math.max(1, p - 1)),
    nextPage: () => setPage((p) => Math.min(list.lastPage, p + 1)),
    search,
    setSearch,
    status,
    setStatus,
    isMutating:
      deleteState.isLoading || createState.isLoading || updateState.isLoading,
    crud,
    submit,
    dedup,
    isDeduping: dedupState.isLoading,
    selection,
    bulkDelete,
  };
}
