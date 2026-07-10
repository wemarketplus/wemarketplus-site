import { useEffect, useState } from 'react';
import { useDebounce } from '@/shared/hooks';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';
import {
  useListWibsQuery,
  useCreateWibMutation,
  useUpdateWibMutation,
  useDeleteWibMutation,
} from '../api/wibsApi';
import { WIBS_PAGE_SIZE, type WibStatus } from '../constants/wibsConstants';
import { toCreateWib, toUpdateWib } from '../utils/wibsUtils';
import type { WibFormValues } from '../schema/wibSchema';
import type { WibRecord } from '../types/wibsTypes';

// Composes the paginated WIBs query (server-side status + state + search filters)
// with the shared CRUD orchestration. Backend `search` matches across
// wibName/wibEmail/wibPhone/state/notes.
export function useWibs() {
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState<WibStatus | ''>('');
  const debouncedSearch = useDebounce(search, 250);

  const [page, setPage] = useState(1);
  useEffect(() => setPage(1), [status, debouncedSearch]);

  const query = useListWibsQuery({
    page,
    limit: WIBS_PAGE_SIZE,
    ...(status ? { status } : {}),
    ...(debouncedSearch.trim() ? { search: debouncedSearch.trim() } : {}),
  });

  const list = usePaginatedList<WibRecord>(query, { pageSize: WIBS_PAGE_SIZE });

  const [createWib, createState] = useCreateWibMutation();
  const [updateWib, updateState] = useUpdateWibMutation();
  const [deleteWib, deleteState] = useDeleteWibMutation();

  const crud = useEntityCrud<
    WibRecord,
    ReturnType<typeof toCreateWib>,
    ReturnType<typeof toUpdateWib>
  >({
    noun: 'WIB',
    create: createWib,
    update: updateWib,
    remove: deleteWib,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (w) => w.wibName,
  });

  const submit = (values: WibFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateWib(values))
      : crud.submitCreate(toCreateWib(values));

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
