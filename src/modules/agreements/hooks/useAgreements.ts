import { useEffect, useState } from 'react';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';
import {
  useListAgreementsQuery,
  useGetAgreementStatsQuery,
  useCreateAgreementMutation,
  useUpdateAgreementMutation,
  useDeleteAgreementMutation,
} from '../api/agreementsApi';
import { AGREEMENTS_PAGE_SIZE, type AgreementStatus } from '../constants/agreementsConstants';
import { toCreateAgreement, toUpdateAgreement } from '../utils/agreementsUtils';
import type { AgreementFormValues } from '../schema/agreementSchema';
import type { AgreementRecord } from '../types/agreementsTypes';

// Composes the paginated agreements query (server-side status filter), the stats
// summary, and the shared CRUD orchestration.
export function useAgreements() {
  const [status, setStatus] = useState<AgreementStatus | ''>('');

  const [page, setPage] = useState(1);
  useEffect(() => setPage(1), [status]);

  const query = useListAgreementsQuery({
    page,
    limit: AGREEMENTS_PAGE_SIZE,
    ...(status ? { status } : {}),
  });

  const list = usePaginatedList<AgreementRecord>(query, { pageSize: AGREEMENTS_PAGE_SIZE });
  const statsQuery = useGetAgreementStatsQuery();

  const [createAgreement, createState] = useCreateAgreementMutation();
  const [updateAgreement, updateState] = useUpdateAgreementMutation();
  const [deleteAgreement, deleteState] = useDeleteAgreementMutation();

  const crud = useEntityCrud<
    AgreementRecord,
    ReturnType<typeof toCreateAgreement>,
    ReturnType<typeof toUpdateAgreement>
  >({
    noun: 'agreement',
    create: createAgreement,
    update: updateAgreement,
    remove: deleteAgreement,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (a) => a.agreementName,
  });

  const submit = (values: AgreementFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateAgreement(values))
      : crud.submitCreate(toCreateAgreement(values));

  return {
    ...list,
    stats: statsQuery.data,
    page,
    prevPage: () => setPage((p) => Math.max(1, p - 1)),
    nextPage: () => setPage((p) => Math.min(list.lastPage, p + 1)),
    status,
    setStatus,
    isMutating: deleteState.isLoading || createState.isLoading || updateState.isLoading,
    crud,
    submit,
  };
}
