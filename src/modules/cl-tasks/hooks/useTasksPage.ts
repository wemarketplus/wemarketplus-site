import { useEffect, useMemo, useState } from 'react';
import { useDebounce } from '@/shared/hooks';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';
import {
  useListClTasksQuery,
  useCreateClTaskMutation,
  useUpdateClTaskMutation,
  useDeleteClTaskMutation,
  type ClTaskRecord,
} from '@/modules/cl-outreach';
import { CL_TASKS_PAGE_SIZE } from '../constants/tasksConstants';
import { toCreateTask, toUpdateTask } from '../utils/tasksUtils';
import type { TaskFormValues } from '../schema/taskSchema';

// The single hook TasksPage consumes: the paginated /cl/tasks query with a
// CLIENT-SIDE search + status filter over the current page. The backend list is
// plain pagination (no search/filter config) and rejects unknown query params
// via forbidNonWhitelisted, so search/status must never hit the wire — they
// narrow the fetched page in-memory (see modules/contacts). Plus the shared
// create/edit/delete orchestration wired to the real task mutations.
export function useTasksPage() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const debouncedSearch = useDebounce(search, 300);

  // Any filter change resets to page 1 (the filtered view is a fresh list).
  useEffect(() => setPage(1), [debouncedSearch, status]);

  const needle = debouncedSearch.trim().toLowerCase();
  const filter = useMemo(
    () => (t: ClTaskRecord) => {
      if (status && t.status !== status) return false;
      if (!needle) return true;
      return (
        t.title.toLowerCase().includes(needle) ||
        (t.description?.toLowerCase().includes(needle) ?? false)
      );
    },
    [needle, status],
  );

  const query = useListClTasksQuery({ page, limit: CL_TASKS_PAGE_SIZE });
  const list = usePaginatedList<ClTaskRecord>(query, {
    pageSize: CL_TASKS_PAGE_SIZE,
    filter,
  });

  const [createTask, createState] = useCreateClTaskMutation();
  const [updateTask, updateState] = useUpdateClTaskMutation();
  const [deleteTask, deleteState] = useDeleteClTaskMutation();

  const crud = useEntityCrud<
    ClTaskRecord,
    ReturnType<typeof toCreateTask>,
    ReturnType<typeof toUpdateTask>
  >({
    noun: 'task',
    create: createTask,
    update: updateTask,
    remove: deleteTask,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (t) => t.title,
  });

  const submit = (values: TaskFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateTask(values))
      : crud.submitCreate(toCreateTask(values));

  // Inline status change from the table's <select> — a targeted PATCH.
  const changeStatus = (task: ClTaskRecord, statusValue: string) =>
    crud.submitUpdate(task.id, { status: statusValue as ClTaskRecord['status'] });

  const hasFilters = Boolean(needle || status);

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
    changeStatus,
  };
}
