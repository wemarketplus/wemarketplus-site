import { useEffect, useState } from 'react';
import { useDebounce } from '@/shared/hooks';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';
import {
  useListClVisitsQuery,
  useCreateClVisitMutation,
  useUpdateClVisitMutation,
  useDeleteClVisitMutation,
} from '../api/clOutreachApi';
import { CL_OUTREACH_PAGE_SIZE } from '../constants/clOutreachConstants';
import { toCreateVisit, toUpdateVisit } from '../utils/clOutreachMappers';
import type { VisitFormValues } from '../schema/clOutreachSchema';
import type { ClOutreachVisitRecord } from '../types/clOutreachApiTypes';

// Outreach-log CRUD: paginated /cl/outreach-visits with server-side search +
// type filter, plus the shared create/edit/delete orchestration. The checkin /
// mileage views read the same records read-only (see useOutreach).
export function useOutreachLog() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [type, setType] = useState('');
  const debouncedSearch = useDebounce(search, 300);

  useEffect(() => setPage(1), [debouncedSearch, type]);

  const query = useListClVisitsQuery({
    page,
    limit: CL_OUTREACH_PAGE_SIZE,
    search: debouncedSearch.trim(),
    type,
  });
  const list = usePaginatedList<ClOutreachVisitRecord>(query, {
    pageSize: CL_OUTREACH_PAGE_SIZE,
  });

  const [createVisit, createState] = useCreateClVisitMutation();
  const [updateVisit, updateState] = useUpdateClVisitMutation();
  const [deleteVisit, deleteState] = useDeleteClVisitMutation();

  const crud = useEntityCrud<
    ClOutreachVisitRecord,
    ReturnType<typeof toCreateVisit>,
    ReturnType<typeof toUpdateVisit>
  >({
    noun: 'visit',
    create: createVisit,
    update: updateVisit,
    remove: deleteVisit,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (v) => v.contactName ?? v.locationName ?? 'visit',
  });

  const submit = (values: VisitFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateVisit(values))
      : crud.submitCreate(toCreateVisit(values));

  const hasFilters = Boolean(debouncedSearch.trim() || type);

  return {
    ...list,
    page,
    prevPage: () => setPage((p) => Math.max(1, p - 1)),
    nextPage: () => setPage((p) => Math.min(list.lastPage, p + 1)),
    search,
    setSearch,
    type,
    setType,
    hasFilters,
    isMutating:
      createState.isLoading || updateState.isLoading || deleteState.isLoading,
    crud,
    submit,
  };
}
