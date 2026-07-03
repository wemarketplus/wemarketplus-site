import { useMemo, useState } from 'react';
import { useDebounce } from '@/shared/hooks';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';
import {
  useListTerritoriesQuery,
  useCreateTerritoryMutation,
  useUpdateTerritoryMutation,
  useDeleteTerritoryMutation,
} from '../api/territoriesApi';
import { TERRITORIES_PAGE_SIZE } from '../constants/territoriesConstants';
import { toCreateTerritory, toUpdateTerritory } from '../utils/territoriesUtils';
import type { TerritoryFormValues } from '../schema/territorySchema';
import type { TerritoryRecord } from '../types/territoriesTypes';

// Single hook the TerritoriesPage consumes: composes the paginated query (the
// backend list is unfiltered, so search is client-side) and shared CRUD.
export function useTerritories() {
  const [search, setSearch] = useState('');
  const debouncedSearch = useDebounce(search, 250);
  const needle = debouncedSearch.trim().toLowerCase();

  const filter = useMemo(
    () => (t: TerritoryRecord) => {
      if (!needle) return true;
      return (
        t.name.toLowerCase().includes(needle) ||
        (t.city?.toLowerCase().includes(needle) ?? false) ||
        (t.state?.toLowerCase().includes(needle) ?? false)
      );
    },
    [needle],
  );

  const [page, setPage] = useState(1);
  const query = useListTerritoriesQuery({ page, limit: TERRITORIES_PAGE_SIZE });

  const list = usePaginatedList<TerritoryRecord>(query, {
    pageSize: TERRITORIES_PAGE_SIZE,
    filter,
  });

  const [createTerritory, createState] = useCreateTerritoryMutation();
  const [updateTerritory, updateState] = useUpdateTerritoryMutation();
  const [deleteTerritory, deleteState] = useDeleteTerritoryMutation();

  const crud = useEntityCrud<
    TerritoryRecord,
    ReturnType<typeof toCreateTerritory>,
    ReturnType<typeof toUpdateTerritory>
  >({
    noun: 'territory',
    create: createTerritory,
    update: updateTerritory,
    remove: deleteTerritory,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (t) => t.name,
  });

  const submit = (values: TerritoryFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateTerritory(values))
      : crud.submitCreate(toCreateTerritory(values));

  return {
    ...list,
    page,
    prevPage: () => setPage((p) => Math.max(1, p - 1)),
    nextPage: () => setPage((p) => Math.min(list.lastPage, p + 1)),
    search,
    setSearch,
    isMutating: deleteState.isLoading || createState.isLoading || updateState.isLoading,
    crud,
    submit,
  };
}
