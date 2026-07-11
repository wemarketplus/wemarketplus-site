import { useEffect, useMemo, useState } from 'react';
import { useDebounce } from '@/shared/hooks';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';
import {
  useListBedUnitsQuery,
  useCreateBedUnitMutation,
  useUpdateBedUnitMutation,
  useDeleteBedUnitMutation,
} from '../api/clinicalApi';
import { CLINICAL_PAGE_SIZE } from '../constants/clinicalTableConstants';
import { bedUnitLabel, toCreateBedUnit, toUpdateBedUnit } from '../utils/bedUnitUtils';
import type { BedUnitFormValues } from '../schema/bedUnitSchema';
import type { BedUnitRecord } from '../types/clinicalApiTypes';

// Bed-units list + create/edit/delete. The backend paginates but does not accept
// search params on this endpoint, so status + free-text narrowing happens
// client-side over the current page via usePaginatedList's `filter`.
export function useBedUnitsPage() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const debouncedSearch = useDebounce(search, 300);

  useEffect(() => setPage(1), [debouncedSearch, status]);

  const query = useListBedUnitsQuery({ page, limit: CLINICAL_PAGE_SIZE });

  const term = debouncedSearch.trim().toLowerCase();
  const filter = useMemo(() => {
    if (!term && !status) return undefined;
    return (unit: BedUnitRecord) => {
      if (status && unit.status !== status) return false;
      if (!term) return true;
      return [unit.facilityName, unit.bedType, unit.patientName]
        .filter(Boolean)
        .some((v) => v!.toLowerCase().includes(term));
    };
  }, [term, status]);

  const list = usePaginatedList<BedUnitRecord>(query, {
    pageSize: CLINICAL_PAGE_SIZE,
    filter,
  });

  const [createUnit, createState] = useCreateBedUnitMutation();
  const [updateUnit, updateState] = useUpdateBedUnitMutation();
  const [deleteUnit, deleteState] = useDeleteBedUnitMutation();

  const crud = useEntityCrud<
    BedUnitRecord,
    ReturnType<typeof toCreateBedUnit>,
    ReturnType<typeof toUpdateBedUnit>
  >({
    noun: 'bed unit',
    create: createUnit,
    update: updateUnit,
    remove: deleteUnit,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: bedUnitLabel,
  });

  const submit = (values: BedUnitFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateBedUnit(values))
      : crud.submitCreate(toCreateBedUnit(values));

  const hasFilters = Boolean(term || status);

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
  };
}
