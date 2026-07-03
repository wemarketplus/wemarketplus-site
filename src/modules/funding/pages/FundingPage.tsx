import { STAFF_ROLES, useRole } from '@/shared/rbac';
import { EntityListPage, EntityPagination } from '@/shared/ui/entity';
import { FundingFilters } from '../components/FundingFilters';
import { FundingTable } from '../components/FundingTable';
import { FundingFormModal } from '../components/FundingFormModal';
import { useFunding } from '../hooks/useFunding';

export function FundingPage() {
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
  } = useFunding();

  // Create is staff-level; mirror the users/contacts convention of gating Add.
  const { isAny } = useRole();
  const canCreate = isAny(STAFF_ROLES);

  return (
    <>
      <EntityListPage
        title="Funding opportunities"
        subtitle={`${total} ${total === 1 ? 'opportunity' : 'opportunities'} tracked`}
        addLabel="Add opportunity"
        onAdd={canCreate ? crud.openCreate : undefined}
        filters={
          <FundingFilters
            search={search}
            onSearch={setSearch}
            status={status}
            onStatus={setStatus}
          />
        }
        isLoading={isLoading}
        error={error}
        errorFallback="Failed to load funding opportunities"
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
        <FundingTable
          rows={rows}
          isMutating={isMutating}
          onEdit={crud.openEdit}
          onDelete={crud.confirmDelete}
        />
      </EntityListPage>

      <FundingFormModal
        open={crud.createOpen || crud.editing !== null}
        isSaving={crud.isSaving}
        editing={crud.editing}
        onClose={crud.editing ? crud.closeEdit : crud.closeCreate}
        onSubmit={submit}
      />
    </>
  );
}
