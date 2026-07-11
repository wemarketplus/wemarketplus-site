import { useEffect, useState } from 'react';
import { useDebounce } from '@/shared/hooks';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';
import {
  useListClCommunitiesQuery,
  useCreateClCommunityMutation,
  useUpdateClCommunityMutation,
  useDeleteClCommunityMutation,
} from '../api/clOperationsApi';
import { CL_OPS_PAGE_SIZE } from '../constants/clOperationsConstants';
import { toCreateCommunity, toUpdateCommunity } from '../utils/clOperationsMappers';
import type { CommunityFormValues } from '../schema/clOperationsSchema';
import type { ClCommunityRecord } from '../types/clOperationsApiTypes';

// Communities CRUD. A community is the parent of every apartment, so this is the
// first thing a tenant must create before Apartment Inventory is usable. The
// /cl/communities list is plain-pagination (no server search), so search is
// applied client-side over the fetched page.
export function useCommunities() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const debouncedSearch = useDebounce(search, 300);
  const needle = debouncedSearch.trim().toLowerCase();

  useEffect(() => setPage(1), [needle]);

  const query = useListClCommunitiesQuery({ page, limit: CL_OPS_PAGE_SIZE });
  const list = usePaginatedList<ClCommunityRecord>(query, {
    pageSize: CL_OPS_PAGE_SIZE,
    filter: (c) =>
      !needle ||
      [c.name, c.city, c.state].filter(Boolean).join(' ').toLowerCase().includes(needle),
  });

  const [createCommunity, createState] = useCreateClCommunityMutation();
  const [updateCommunity, updateState] = useUpdateClCommunityMutation();
  const [deleteCommunity, deleteState] = useDeleteClCommunityMutation();

  const crud = useEntityCrud<
    ClCommunityRecord,
    ReturnType<typeof toCreateCommunity>,
    ReturnType<typeof toUpdateCommunity>
  >({
    noun: 'community',
    create: createCommunity,
    update: updateCommunity,
    remove: deleteCommunity,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (c) => c.name,
  });

  const submit = (values: CommunityFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateCommunity(values))
      : crud.submitCreate(toCreateCommunity(values));

  return {
    ...list,
    page,
    prevPage: () => setPage((p) => Math.max(1, p - 1)),
    nextPage: () => setPage((p) => Math.min(list.lastPage, p + 1)),
    search,
    setSearch,
    hasFilters: Boolean(needle),
    isMutating: createState.isLoading || updateState.isLoading || deleteState.isLoading,
    crud,
    submit,
  };
}
