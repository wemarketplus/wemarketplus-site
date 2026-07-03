import { STAFF_ROLES, useRole } from '@/shared/rbac';
import { EntityListPage, EntityPagination } from '@/shared/ui/entity';
import { AgreementsFilters } from '../components/AgreementsFilters';
import { AgreementsTable } from '../components/AgreementsTable';
import { AgreementFormModal } from '../components/AgreementFormModal';
import { AgreementStats } from '../components/AgreementStats';
import { useAgreements } from '../hooks/useAgreements';

export function AgreementsPage() {
  const {
    rows,
    total,
    stats,
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
  } = useAgreements();

  // Create is staff-level; mirror the users/contacts convention of gating Add.
  const { isAny } = useRole();
  const canCreate = isAny(STAFF_ROLES);

  return (
    <>
      <div className="space-y-6">
        <AgreementStats stats={stats} />

        <EntityListPage
          title="Agreements"
          subtitle={`${total} ${total === 1 ? 'agreement' : 'agreements'} tracked`}
          addLabel="Add agreement"
          onAdd={canCreate ? crud.openCreate : undefined}
          filters={<AgreementsFilters status={status} onStatus={setStatus} />}
          isLoading={isLoading}
          error={error}
          errorFallback="Failed to load agreements"
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
          <AgreementsTable
            rows={rows}
            isMutating={isMutating}
            onEdit={crud.openEdit}
            onDelete={crud.confirmDelete}
          />
        </EntityListPage>
      </div>

      <AgreementFormModal
        open={crud.createOpen || crud.editing !== null}
        isSaving={crud.isSaving}
        editing={crud.editing}
        onClose={crud.editing ? crud.closeEdit : crud.closeCreate}
        onSubmit={submit}
      />
    </>
  );
}
