import { useEffect, useState } from 'react';
import { useDebounce } from '@/shared/hooks';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';
import {
  useListFundingQuery,
  useCreateFundingMutation,
  useUpdateFundingMutation,
  useDeleteFundingMutation,
} from '../api/fundingApi';
import { FUNDING_PAGE_SIZE, type FundingStatus } from '../constants/fundingConstants';
import { toCreateFunding, toUpdateFunding } from '../utils/fundingUtils';
import type { FundingFormValues } from '../schema/fundingSchema';
import type { FundingRecord } from '../types/fundingTypes';

// Composes the paginated funding query (server-side status filter + search) with
// the shared CRUD orchestration. Backend `search` matches opportunityName.
export function useFunding() {
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState<FundingStatus | ''>('');
  const debouncedSearch = useDebounce(search, 250);

  const [page, setPage] = useState(1);
  // status + search are server filters — reset to page 1 whenever they change.
  useEffect(() => setPage(1), [status, debouncedSearch]);

  const query = useListFundingQuery({
    page,
    limit: FUNDING_PAGE_SIZE,
    ...(status ? { status } : {}),
    ...(debouncedSearch.trim() ? { search: debouncedSearch.trim() } : {}),
  });

  const list = usePaginatedList<FundingRecord>(query, { pageSize: FUNDING_PAGE_SIZE });

  const [createFunding, createState] = useCreateFundingMutation();
  const [updateFunding, updateState] = useUpdateFundingMutation();
  const [deleteFunding, deleteState] = useDeleteFundingMutation();

  const crud = useEntityCrud<
    FundingRecord,
    ReturnType<typeof toCreateFunding>,
    ReturnType<typeof toUpdateFunding>
  >({
    noun: 'opportunity',
    create: createFunding,
    update: updateFunding,
    remove: deleteFunding,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (f) => f.opportunityName,
  });

  const submit = (values: FundingFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateFunding(values))
      : crud.submitCreate(toCreateFunding(values));

  return {
    ...list,
    page,
    prevPage: () => setPage((p) => Math.max(1, p - 1)),
    nextPage: () => setPage((p) => Math.min(list.lastPage, p + 1)),
    search,
    setSearch,
    status,
    setStatus,
    isMutating: deleteState.isLoading || createState.isLoading || updateState.isLoading,
    crud,
    submit,
  };
}
