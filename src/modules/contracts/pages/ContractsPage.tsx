// Contracts CRUD built on the shared entity kit (@/shared/ui/entity). Mirrors
// ContactsPage. Delete is Admin/Owner-only (gated in ContractsTable + enforced
// by the backend @Roles guard); create/edit are open to any authenticated user
// on the backend, but we gate the Add button to staff per convention.
import { STAFF_ROLES, useRole } from '@/shared/rbac';
import { EntityListPage, EntityPagination } from '@/shared/ui/entity';
import { ContractsFilters } from '../components/ContractsFilters';
import { ContractsTable } from '../components/ContractsTable';
import { ContractFormModal } from '../components/ContractFormModal';
import { useContracts } from '../hooks/useContracts';

export function ContractsPage() {
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
  } = useContracts();

  const { isAny } = useRole();
  const canCreate = isAny(STAFF_ROLES);

  return (
    <>
      <EntityListPage
        title="Contracts"
        subtitle={`${total} ${total === 1 ? 'contract' : 'contracts'}`}
        addLabel="New contract"
        onAdd={canCreate ? crud.openCreate : undefined}
        filters={
          <ContractsFilters
            search={search}
            onSearch={setSearch}
            status={status}
            onStatus={setStatus}
          />
        }
        isLoading={isLoading}
        error={error}
        errorFallback="Failed to load contracts"
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
        <ContractsTable
          contracts={rows}
          isMutating={isMutating}
          onEdit={crud.openEdit}
          onDelete={crud.confirmDelete}
        />
      </EntityListPage>

      <ContractFormModal
        open={crud.createOpen || crud.editing !== null}
        isSaving={crud.isSaving}
        editing={crud.editing}
        onClose={crud.editing ? crud.closeEdit : crud.closeCreate}
        onSubmit={submit}
      />
    </>
  );
}
