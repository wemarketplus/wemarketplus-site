import { useEffect, useState } from 'react';
import { useDebounce } from '@/shared/hooks';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';
import {
  useListTrainingProvidersQuery,
  useCreateTrainingProviderMutation,
  useUpdateTrainingProviderMutation,
  useDeleteTrainingProviderMutation,
} from '../api/trainingApi';
import { TRAINING_PROVIDERS_PAGE_SIZE } from '../constants/trainingConstants';
import {
  toCreateTrainingProvider,
  toUpdateTrainingProvider,
} from '../utils/trainingProvidersUtils';
import type { TrainingProviderFormValues } from '../schema/trainingProviderSchema';
import type { TrainingProviderRecord } from '../types/trainingTypes';

// Single hook the TrainingProvidersPage consumes: composes the paginated query
// (server-side name search) and the shared CRUD orchestration.
export function useTrainingProviders() {
  const [search, setSearch] = useState('');
  const debouncedSearch = useDebounce(search, 250);

  const [page, setPage] = useState(1);
  useEffect(() => setPage(1), [debouncedSearch]);

  const query = useListTrainingProvidersQuery({
    page,
    limit: TRAINING_PROVIDERS_PAGE_SIZE,
    ...(debouncedSearch.trim() ? { search: debouncedSearch.trim() } : {}),
  });

  const list = usePaginatedList<TrainingProviderRecord>(query, {
    pageSize: TRAINING_PROVIDERS_PAGE_SIZE,
  });

  const [createProvider, createState] = useCreateTrainingProviderMutation();
  const [updateProvider, updateState] = useUpdateTrainingProviderMutation();
  const [deleteProvider, deleteState] = useDeleteTrainingProviderMutation();

  const crud = useEntityCrud<
    TrainingProviderRecord,
    ReturnType<typeof toCreateTrainingProvider>,
    ReturnType<typeof toUpdateTrainingProvider>
  >({
    noun: 'training provider',
    create: createProvider,
    update: updateProvider,
    remove: deleteProvider,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (p) => p.name,
  });

  const submit = (values: TrainingProviderFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateTrainingProvider(values))
      : crud.submitCreate(toCreateTrainingProvider(values));

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
