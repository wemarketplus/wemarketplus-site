import { useEffect, useState } from 'react';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';
import {
  useListApplicationsQuery,
  useCreateApplicationMutation,
  useUpdateApplicationMutation,
  useDeleteApplicationMutation,
} from '../api/applicationsApi';
import { APPLICATIONS_PAGE_SIZE, type ApplicationStatus } from '../constants/applicationsConstants';
import { toCreateApplication, toUpdateApplication } from '../utils/applicationsUtils';
import type { ApplicationFormValues } from '../schema/applicationSchema';
import type { ApplicationRecord } from '../types/applicationsTypes';

// Composes the paginated applications query (server-side status filter) with the
// shared CRUD orchestration.
export function useApplications() {
  const [status, setStatus] = useState<ApplicationStatus | ''>('');

  const [page, setPage] = useState(1);
  useEffect(() => setPage(1), [status]);

  const query = useListApplicationsQuery({
    page,
    limit: APPLICATIONS_PAGE_SIZE,
    ...(status ? { status } : {}),
  });

  const list = usePaginatedList<ApplicationRecord>(query, { pageSize: APPLICATIONS_PAGE_SIZE });

  const [createApplication, createState] = useCreateApplicationMutation();
  const [updateApplication, updateState] = useUpdateApplicationMutation();
  const [deleteApplication, deleteState] = useDeleteApplicationMutation();

  const crud = useEntityCrud<
    ApplicationRecord,
    ReturnType<typeof toCreateApplication>,
    ReturnType<typeof toUpdateApplication>
  >({
    noun: 'application',
    create: createApplication,
    update: updateApplication,
    remove: deleteApplication,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (a) => a.applicationNumber ?? a.id,
  });

  const submit = (values: ApplicationFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateApplication(values))
      : crud.submitCreate(toCreateApplication(values));

  return {
    ...list,
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
