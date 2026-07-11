import { useEffect, useState } from 'react';
import { useDebounce } from '@/shared/hooks';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';
import {
  useListClCompetitorsQuery,
  useCreateClCompetitorMutation,
  useUpdateClCompetitorMutation,
  useDeleteClCompetitorMutation,
} from '../api/clFinancialApi';
import { CL_FINANCIAL_PAGE_SIZE } from '../constants/clFinancialConstants';
import { toCreateCompetitor, toUpdateCompetitor } from '../utils/clFinancialMappers';
import type { CompetitorFormValues } from '../schema/clFinancialSchema';
import type { ClCompetitorRecord } from '../types/clFinancialApiTypes';

// Competitor intel CRUD: paginated /cl/competitors with server-side search.
export function useCompetitors() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const debouncedSearch = useDebounce(search, 300);

  useEffect(() => setPage(1), [debouncedSearch]);

  const query = useListClCompetitorsQuery({
    page,
    limit: CL_FINANCIAL_PAGE_SIZE,
    search: debouncedSearch.trim(),
  });
  const list = usePaginatedList<ClCompetitorRecord>(query, { pageSize: CL_FINANCIAL_PAGE_SIZE });

  const [createCompetitor, createState] = useCreateClCompetitorMutation();
  const [updateCompetitor, updateState] = useUpdateClCompetitorMutation();
  const [deleteCompetitor, deleteState] = useDeleteClCompetitorMutation();

  const crud = useEntityCrud<
    ClCompetitorRecord,
    ReturnType<typeof toCreateCompetitor>,
    ReturnType<typeof toUpdateCompetitor>
  >({
    noun: 'competitor',
    create: createCompetitor,
    update: updateCompetitor,
    remove: deleteCompetitor,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (c) => c.name,
  });

  const submit = (values: CompetitorFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateCompetitor(values))
      : crud.submitCreate(toCreateCompetitor(values));

  const hasFilters = Boolean(debouncedSearch.trim());

  return {
    ...list,
    page,
    prevPage: () => setPage((p) => Math.max(1, p - 1)),
    nextPage: () => setPage((p) => Math.min(list.lastPage, p + 1)),
    search,
    setSearch,
    hasFilters,
    isMutating: createState.isLoading || updateState.isLoading || deleteState.isLoading,
    crud,
    submit,
  };
}
