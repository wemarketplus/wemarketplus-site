import { useEffect, useState } from 'react';
import { useDebounce } from '@/shared/hooks';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';
import {
  useListLocationsQuery,
  useCreateLocationMutation,
  useUpdateLocationMutation,
  useDeleteLocationMutation,
} from '../api/locationsApi';
import { LOCATIONS_PAGE_SIZE } from '../constants/locationsConstants';
import { toCreateLocation, toUpdateLocation } from '../utils/locationsUtils';
import type { LocationStatus } from '../constants/locationsConstants';
import type { LocationFormValues } from '../schema/locationSchema';
import type { LocationRecord } from '../types/locationsTypes';

// Single hook the LocationsPage consumes: composes the paginated query (with
// server-side search/status/state filters) and the shared CRUD orchestration.
export function useLocations() {
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const [state, setState] = useState('');
  const debouncedSearch = useDebounce(search, 250);
  const debouncedState = useDebounce(state, 250);

  // Page state lives here so it exists before the query runs and can be fed
  // straight into it. Server filters reset the list, so reset to page 1 on change.
  const [page, setPage] = useState(1);
  useEffect(() => setPage(1), [debouncedSearch, status, debouncedState]);

  const query = useListLocationsQuery({
    page,
    limit: LOCATIONS_PAGE_SIZE,
    ...(debouncedSearch.trim() ? { search: debouncedSearch.trim() } : {}),
    ...(status ? { status: status as LocationStatus } : {}),
    ...(debouncedState.trim() ? { state: debouncedState.trim() } : {}),
  });

  const list = usePaginatedList<LocationRecord>(query, { pageSize: LOCATIONS_PAGE_SIZE });

  const [createLocation, createState] = useCreateLocationMutation();
  const [updateLocation, updateState] = useUpdateLocationMutation();
  const [deleteLocation, deleteState] = useDeleteLocationMutation();

  const crud = useEntityCrud<
    LocationRecord,
    ReturnType<typeof toCreateLocation>,
    ReturnType<typeof toUpdateLocation>
  >({
    noun: 'location',
    create: createLocation,
    update: updateLocation,
    remove: deleteLocation,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (l) => l.locationName,
  });

  const submit = (values: LocationFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateLocation(values))
      : crud.submitCreate(toCreateLocation(values));

  return {
    ...list,
    page,
    prevPage: () => setPage((p) => Math.max(1, p - 1)),
    nextPage: () => setPage((p) => Math.min(list.lastPage, p + 1)),
    search,
    setSearch,
    status,
    setStatus,
    state,
    setState,
    isMutating: deleteState.isLoading || createState.isLoading || updateState.isLoading,
    crud,
    submit,
  };
}
