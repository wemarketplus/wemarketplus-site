import { useEffect, useState } from 'react';
import { useDebounce } from '@/shared/hooks';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';
import {
  useListClLocPricingQuery,
  useCreateClLocPricingMutation,
  useUpdateClLocPricingMutation,
  useDeleteClLocPricingMutation,
} from '../api/clFinancialApi';
import { CL_FINANCIAL_PAGE_SIZE } from '../constants/clFinancialConstants';
import { toCreateLoc, toUpdateLoc } from '../utils/clFinancialMappers';
import type { LocFormValues } from '../schema/clFinancialSchema';
import type { ClLocPricingRecord } from '../types/clFinancialApiTypes';

// LOC calculator CRUD: paginated /cl/loc-pricing (level-based care add-on rates).
export function useLocPricing() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const debouncedSearch = useDebounce(search, 300);

  useEffect(() => setPage(1), [debouncedSearch]);

  const query = useListClLocPricingQuery({
    page,
    limit: CL_FINANCIAL_PAGE_SIZE,
    search: debouncedSearch.trim(),
  });
  const list = usePaginatedList<ClLocPricingRecord>(query, { pageSize: CL_FINANCIAL_PAGE_SIZE });

  const [createLoc, createState] = useCreateClLocPricingMutation();
  const [updateLoc, updateState] = useUpdateClLocPricingMutation();
  const [deleteLoc, deleteState] = useDeleteClLocPricingMutation();

  const crud = useEntityCrud<
    ClLocPricingRecord,
    ReturnType<typeof toCreateLoc>,
    ReturnType<typeof toUpdateLoc>
  >({
    noun: 'level',
    create: createLoc,
    update: updateLoc,
    remove: deleteLoc,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (l) => l.label,
  });

  const submit = (values: LocFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateLoc(values))
      : crud.submitCreate(toCreateLoc(values));

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
