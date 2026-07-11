import { useEffect, useMemo, useState } from 'react';
import { useDebounce } from '@/shared/hooks';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';
import {
  useListTelehealthQuery,
  useCreateTelehealthMutation,
  useUpdateTelehealthMutation,
  useDeleteTelehealthMutation,
} from '../api/clinicalApi';
import { CLINICAL_PAGE_SIZE } from '../constants/clinicalTableConstants';
import {
  telehealthLabel,
  toCreateTelehealth,
  toUpdateTelehealth,
} from '../utils/telehealthUtils';
import type { TelehealthFormValues } from '../schema/telehealthSchema';
import type { TelehealthSessionRecord } from '../types/clinicalApiTypes';

// Telehealth sessions list + create/edit/delete. Status + free-text narrowing is
// client-side over the current page (the list endpoint only accepts pagination
// here) to avoid a forbidNonWhitelisted 400.
export function useTelehealthPage() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const debouncedSearch = useDebounce(search, 300);

  useEffect(() => setPage(1), [debouncedSearch, status]);

  const query = useListTelehealthQuery({ page, limit: CLINICAL_PAGE_SIZE });

  const term = debouncedSearch.trim().toLowerCase();
  const filter = useMemo(() => {
    if (!term && !status) return undefined;
    return (session: TelehealthSessionRecord) => {
      if (status && session.status !== status) return false;
      if (!term) return true;
      return [session.patientName, session.providerName, session.sessionType]
        .filter(Boolean)
        .some((v) => v!.toLowerCase().includes(term));
    };
  }, [term, status]);

  const list = usePaginatedList<TelehealthSessionRecord>(query, {
    pageSize: CLINICAL_PAGE_SIZE,
    filter,
  });

  const [createSession, createState] = useCreateTelehealthMutation();
  const [updateSession, updateState] = useUpdateTelehealthMutation();
  const [deleteSession, deleteState] = useDeleteTelehealthMutation();

  const crud = useEntityCrud<
    TelehealthSessionRecord,
    ReturnType<typeof toCreateTelehealth>,
    ReturnType<typeof toUpdateTelehealth>
  >({
    noun: 'session',
    create: createSession,
    update: updateSession,
    remove: deleteSession,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: telehealthLabel,
  });

  const submit = (values: TelehealthFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateTelehealth(values))
      : crud.submitCreate(toCreateTelehealth(values));

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
