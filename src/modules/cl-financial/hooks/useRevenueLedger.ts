import { useEffect, useState } from 'react';
import { useDebounce } from '@/shared/hooks';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';
import {
  useListClRevenueQuery,
  useCreateClRevenueMutation,
  useUpdateClRevenueMutation,
  useDeleteClRevenueMutation,
} from '../api/clFinancialApi';
import { CL_FINANCIAL_PAGE_SIZE } from '../constants/clFinancialConstants';
import { toCreateRevenue, toUpdateRevenue } from '../utils/clFinancialMappers';
import type { RevenueFormValues } from '../schema/clFinancialSchema';
import type { ClRevenueEntryRecord } from '../types/clFinancialApiTypes';

// Revenue ledger CRUD: paginated /cl/revenue-entries with server-side search.
export function useRevenueLedger() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const debouncedSearch = useDebounce(search, 300);

  useEffect(() => setPage(1), [debouncedSearch]);

  const query = useListClRevenueQuery({
    page,
    limit: CL_FINANCIAL_PAGE_SIZE,
    search: debouncedSearch.trim(),
  });
  const list = usePaginatedList<ClRevenueEntryRecord>(query, { pageSize: CL_FINANCIAL_PAGE_SIZE });

  const [createRevenue, createState] = useCreateClRevenueMutation();
  const [updateRevenue, updateState] = useUpdateClRevenueMutation();
  const [deleteRevenue, deleteState] = useDeleteClRevenueMutation();

  const crud = useEntityCrud<
    ClRevenueEntryRecord,
    ReturnType<typeof toCreateRevenue>,
    ReturnType<typeof toUpdateRevenue>
  >({
    noun: 'entry',
    create: createRevenue,
    update: updateRevenue,
    remove: deleteRevenue,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (r) => r.category ?? 'entry',
  });

  const submit = (values: RevenueFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateRevenue(values))
      : crud.submitCreate(toCreateRevenue(values));

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
