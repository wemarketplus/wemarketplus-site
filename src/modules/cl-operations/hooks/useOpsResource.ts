import { useEffect, useState } from 'react';
import { useDebounce } from '@/shared/hooks';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';

type MutationTrigger<TArg, TResult> = (arg: TArg) => { unwrap: () => Promise<TResult> };

interface OpsQueryResult<T> {
  data?: { data: T[]; total: number };
  isLoading: boolean;
  isFetching: boolean;
  error?: unknown;
  refetch: () => void;
}

interface UseOpsResourceArgs<TEntity extends { id: string }, TCreate, TUpdate, TForm> {
  noun: string;
  pageSize: number;
  useListQuery: (params: { page: number; limit: number; search: string; status: string }) => OpsQueryResult<TEntity>;
  create: MutationTrigger<TCreate, TEntity>;
  createState: { isLoading: boolean };
  update: MutationTrigger<{ id: string; patch: TUpdate }, TEntity>;
  updateState: { isLoading: boolean };
  remove: MutationTrigger<string, unknown>;
  removeState: { isLoading: boolean };
  toCreate: (values: TForm) => TCreate;
  toUpdate: (values: TForm) => TUpdate;
  labelOf: (entity: TEntity) => string;
}

// Shared orchestration for a CommunityLink operations resource: paginated list
// with server-side search + status filter, the standard create/edit/delete
// lifecycle, and an inline status change. Each of the four ops views (apartments,
// make-ready, maintenance, housekeeping) wires this with its own mutations.
export function useOpsResource<
  TEntity extends { id: string; status: string },
  TCreate,
  TUpdate,
  TForm,
>({
  noun,
  pageSize,
  useListQuery,
  create,
  createState,
  update,
  updateState,
  remove,
  removeState,
  toCreate,
  toUpdate,
  labelOf,
}: UseOpsResourceArgs<TEntity, TCreate, TUpdate, TForm>) {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const debouncedSearch = useDebounce(search, 300);

  useEffect(() => setPage(1), [debouncedSearch, status]);

  const query = useListQuery({ page, limit: pageSize, search: debouncedSearch.trim(), status });
  const list = usePaginatedList<TEntity>(query, { pageSize });

  const crud = useEntityCrud<TEntity, TCreate, TUpdate>({
    noun,
    create,
    update,
    remove,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf,
  });

  const submit = (values: TForm) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdate(values))
      : crud.submitCreate(toCreate(values));

  const changeStatus = (entity: TEntity, statusValue: string) =>
    crud.submitUpdate(entity.id, { status: statusValue } as TUpdate);

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
    isMutating: createState.isLoading || updateState.isLoading || removeState.isLoading,
    crud,
    submit,
    changeStatus,
  };
}
