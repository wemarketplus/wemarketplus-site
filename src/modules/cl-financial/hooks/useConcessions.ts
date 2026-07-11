import { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { useDebounce } from '@/shared/hooks';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';
import {
  useListClConcessionsQuery,
  useCreateClConcessionMutation,
  useUpdateClConcessionMutation,
  useDeleteClConcessionMutation,
} from '../api/clFinancialApi';
import { CONCESSION_STATUS } from '../constants/clFinancialApiConstants';
import { CL_FINANCIAL_PAGE_SIZE } from '../constants/clFinancialConstants';
import { toCreateConcession, toUpdateConcession } from '../utils/clFinancialMappers';
import type { ConcessionFormValues } from '../schema/clFinancialSchema';
import type { ClConcessionRecord } from '../types/clFinancialApiTypes';

// Concession approvals CRUD: paginated /cl/concessions with server-side search +
// status filter, plus approve / reject actions (the backend stamps the reviewer).
export function useConcessions() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const debouncedSearch = useDebounce(search, 300);

  useEffect(() => setPage(1), [debouncedSearch, status]);

  const query = useListClConcessionsQuery({
    page,
    limit: CL_FINANCIAL_PAGE_SIZE,
    search: debouncedSearch.trim(),
    status,
  });
  const list = usePaginatedList<ClConcessionRecord>(query, { pageSize: CL_FINANCIAL_PAGE_SIZE });

  const [createConcession, createState] = useCreateClConcessionMutation();
  const [updateConcession, updateState] = useUpdateClConcessionMutation();
  const [deleteConcession, deleteState] = useDeleteClConcessionMutation();

  const crud = useEntityCrud<
    ClConcessionRecord,
    ReturnType<typeof toCreateConcession>,
    ReturnType<typeof toUpdateConcession>
  >({
    noun: 'concession',
    create: createConcession,
    update: updateConcession,
    remove: deleteConcession,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (c) => c.type,
  });

  const submit = (values: ConcessionFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateConcession(values))
      : crud.submitCreate(toCreateConcession(values));

  const decide = async (c: ClConcessionRecord, decision: 'approved' | 'rejected') => {
    try {
      await updateConcession({
        id: c.id,
        patch: {
          status:
            decision === 'approved' ? CONCESSION_STATUS.Approved : CONCESSION_STATUS.Rejected,
        },
      }).unwrap();
      toast.success(decision === 'approved' ? 'Concession approved' : 'Concession rejected');
    } catch {
      toast.error('Could not update the concession.');
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
    decide,
  };
}
