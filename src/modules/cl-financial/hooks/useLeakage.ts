import { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { useDebounce } from '@/shared/hooks';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';
import {
  useListClLeakageItemsQuery,
  useCreateClLeakageItemMutation,
  useUpdateClLeakageItemMutation,
  useDeleteClLeakageItemMutation,
} from '../api/clFinancialApi';
import { LEAKAGE_STATUS } from '../constants/clFinancialApiConstants';
import { CL_FINANCIAL_PAGE_SIZE } from '../constants/clFinancialConstants';
import { toCreateLeakage, toUpdateLeakage } from '../utils/clFinancialMappers';
import type { LeakageFormValues } from '../schema/clFinancialSchema';
import type { ClLeakageItemRecord } from '../types/clFinancialApiTypes';

// Revenue leakage CRUD: paginated /cl/leakage-items with server-side search +
// status filter, plus a resolve action (the backend stamps the resolver).
export function useLeakage() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const debouncedSearch = useDebounce(search, 300);

  useEffect(() => setPage(1), [debouncedSearch, status]);

  const query = useListClLeakageItemsQuery({
    page,
    limit: CL_FINANCIAL_PAGE_SIZE,
    search: debouncedSearch.trim(),
    status,
  });
  const list = usePaginatedList<ClLeakageItemRecord>(query, { pageSize: CL_FINANCIAL_PAGE_SIZE });

  const [createItem, createState] = useCreateClLeakageItemMutation();
  const [updateItem, updateState] = useUpdateClLeakageItemMutation();
  const [deleteItem, deleteState] = useDeleteClLeakageItemMutation();

  const crud = useEntityCrud<
    ClLeakageItemRecord,
    ReturnType<typeof toCreateLeakage>,
    ReturnType<typeof toUpdateLeakage>
  >({
    noun: 'leakage item',
    create: createItem,
    update: updateItem,
    remove: deleteItem,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (l) => l.issue,
  });

  const submit = (values: LeakageFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateLeakage(values))
      : crud.submitCreate(toCreateLeakage(values));

  const resolve = async (l: ClLeakageItemRecord) => {
    try {
      await updateItem({ id: l.id, patch: { status: LEAKAGE_STATUS.Resolved } }).unwrap();
      toast.success('Leakage item resolved');
    } catch {
      toast.error('Could not update the leakage item.');
    }
  };

  const hasFilters = Boolean(debouncedSearch.trim() || status);

  return {
    ...list,
    page,
    prevPage: () => setPage((p) => Math.max(1, p - 1)),
    nextPage: () => setPage((p) => Math.min(list.lastPage, p + 1)),
    search,
    setSearch,
    status,
    setStatus,
    hasFilters,
    isMutating: createState.isLoading || updateState.isLoading || deleteState.isLoading,
    crud,
    submit,
    resolve,
  };
}
