import { STAFF_ROLES, useRole } from '@/shared/rbac';
import { EntityListPage, EntityPagination } from '@/shared/ui/entity';
import { WibsFilters } from '../components/WibsFilters';
import { WibsTable } from '../components/WibsTable';
import { WibFormModal } from '../components/WibFormModal';
import { useWibs } from '../hooks/useWibs';

export function WibsPage() {
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
    search,
    setSearch,
    status,
    setStatus,
    isMutating,
    crud,
    submit,
  } = useWibs();

  // Create is staff-level; mirror the users/contacts convention of gating Add.
  const { isAny } = useRole();
  const canCreate = isAny(STAFF_ROLES);

  return (
    <>
      <EntityListPage
        title="Workforce Investment Boards"
        subtitle={`${total} ${total === 1 ? 'board' : 'boards'} tracked`}
        addLabel="Add WIB"
        onAdd={canCreate ? crud.openCreate : undefined}
        filters={
          <WibsFilters
            search={search}
            onSearch={setSearch}
            status={status}
            onStatus={setStatus}
          />
        }
        isLoading={isLoading}
        error={error}
        errorFallback="Failed to load WIBs"
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
        <WibsTable
          rows={rows}
          isMutating={isMutating}
          onEdit={crud.openEdit}
          onDelete={crud.confirmDelete}
        />
      </EntityListPage>

      <WibFormModal
        open={crud.createOpen || crud.editing !== null}
        isSaving={crud.isSaving}
        editing={crud.editing}
        onClose={crud.editing ? crud.closeEdit : crud.closeCreate}
        onSubmit={submit}
      />
    </>
  );
}
