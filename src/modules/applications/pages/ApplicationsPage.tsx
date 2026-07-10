import { STAFF_ROLES, useRole } from '@/shared/rbac';
import { EntityListPage, EntityPagination } from '@/shared/ui/entity';
import { ApplicationsFilters } from '../components/ApplicationsFilters';
import { ApplicationsTable } from '../components/ApplicationsTable';
import { ApplicationFormModal } from '../components/ApplicationFormModal';
import { useApplications } from '../hooks/useApplications';

export function ApplicationsPage() {
  const {
    rows,
    total,
    page,
    lastPage,
    prevPage,
    nextPage,
    isLoading,
    isFetching,
    error,
    status,
    setStatus,
    isMutating,
    crud,
    submit,
  } = useApplications();

  // Create is staff-level; mirror the users/contacts convention of gating Add.
  const { isAny } = useRole();
  const canCreate = isAny(STAFF_ROLES);

  return (
    <>
      <EntityListPage
        title="Applications"
        subtitle={`${total} ${total === 1 ? 'application' : 'applications'} tracked`}
        addLabel="Add application"
        onAdd={canCreate ? crud.openCreate : undefined}
        filters={<ApplicationsFilters status={status} onStatus={setStatus} />}
        isLoading={isLoading}
        error={error}
        errorFallback="Failed to load applications"
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
        <ApplicationsTable
          rows={rows}
          isMutating={isMutating}
          onEdit={crud.openEdit}
          onDelete={crud.confirmDelete}
        />
      </EntityListPage>

      <ApplicationFormModal
        open={crud.createOpen || crud.editing !== null}
        isSaving={crud.isSaving}
        editing={crud.editing}
        onClose={crud.editing ? crud.closeEdit : crud.closeCreate}
        onSubmit={submit}
      />
    </>
  );
}
