import { useRole, CL_ALL_ROLES } from '@/shared/rbac';
import { EntityListPage, EntityPagination } from '@/shared/ui/entity';
import { TasksFilters } from '../components/TasksFilters';
import { TasksTable } from '../components/TasksTable';
import { TaskFormModal } from '../components/TaskFormModal';
import { useTasksPage } from '../hooks/useTasksPage';

export function TasksPage() {
  const {
    rows,
    total,
    page,
    lastPage,
    isLoading,
    isFetching,
    error,
    prevPage,
    nextPage,
    search,
    setSearch,
    status,
    setStatus,
    hasFilters,
    isMutating,
    crud,
    submit,
    changeStatus,
  } = useTasksPage();

  // Add/edit is a staff action; read-only roles see the list without the CTA.
  const { isAny } = useRole();
  const canEdit = isAny(CL_ALL_ROLES);

  return (
    <EntityListPage
      title="Tasks"
      subtitle={`${total} tasks across the community`}
      addLabel="Add Task"
      onAdd={canEdit ? crud.openCreate : undefined}
      isLoading={isLoading}
      error={error}
      errorFallback="Failed to load tasks"
      filters={
        <TasksFilters
          search={search}
          status={status}
          onSearch={setSearch}
          onStatus={setStatus}
        />
      }
      pagination={
        <EntityPagination
          page={page}
          lastPage={lastPage}
          isFetching={isFetching}
          onPrev={prevPage}
          onNext={nextPage}
        />
      }
    >
      <TasksTable
        tasks={rows}
        isMutating={isMutating}
        hasFilters={hasFilters}
        onEdit={crud.openEdit}
        onDelete={crud.confirmDelete}
        onStatusChange={changeStatus}
        onAdd={canEdit ? crud.openCreate : undefined}
      />

      <TaskFormModal
        open={crud.createOpen || crud.editing !== null}
        isSaving={crud.isSaving}
        editing={crud.editing}
        onClose={crud.editing ? crud.closeEdit : crud.closeCreate}
        onSubmit={submit}
      />
    </EntityListPage>
  );
}
