import { useMemo, useState } from 'react';
import { useDebounce } from '@/shared/hooks';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';
import {
  useListContractsQuery,
  useCreateContractMutation,
  useUpdateContractMutation,
  useDeleteContractMutation,
} from '../api/contractsApi';
import { CONTRACTS_PAGE_SIZE } from '../constants/contractsConstants';
import { toCreateContract, toUpdateContract } from '../utils/contractsUtils';
import type { ContractFormValues } from '../schema/contractSchema';
import type { ContractRecord } from '../types/contractsTypes';

// Single hook the ContractsPage consumes: composes the paginated query (the
// backend has no filters, so status/search are client-side) with the shared
// CRUD orchestration (create + update + delete).
export function useContracts() {
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const debouncedSearch = useDebounce(search, 250);

  const needle = debouncedSearch.trim().toLowerCase();
  const filter = useMemo(
    () => (c: ContractRecord) => {
      if (status && c.status !== status) return false;
      if (!needle) return true;
      return (
        c.companyName.toLowerCase().includes(needle) ||
        c.contractNumber.toLowerCase().includes(needle) ||
        (c.contractType?.toLowerCase().includes(needle) ?? false)
      );
    },
    [needle, status],
  );

  const [page, setPage] = useState(1);

  const query = useListContractsQuery({ page, limit: CONTRACTS_PAGE_SIZE });

  const list = usePaginatedList<ContractRecord>(query, {
    pageSize: CONTRACTS_PAGE_SIZE,
    filter,
  });

  const [createContract, createState] = useCreateContractMutation();
  const [updateContract, updateState] = useUpdateContractMutation();
  const [deleteContract, deleteState] = useDeleteContractMutation();

  const crud = useEntityCrud<
    ContractRecord,
    ReturnType<typeof toCreateContract>,
    ReturnType<typeof toUpdateContract>
  >({
    noun: 'contract',
    create: createContract,
    update: updateContract,
    remove: deleteContract,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (c) => c.contractNumber,
  });

  const submit = (values: ContractFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateContract(values))
      : crud.submitCreate(toCreateContract(values));

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
