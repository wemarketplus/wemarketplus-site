import { useRole, CL_SALES_ROLES } from '@/shared/rbac';
import { EntityListPage, EntityPagination } from '@/shared/ui/entity';
import { ReferralsFilters } from '../components/ReferralsFilters';
import { ClReferralsTable } from '../components/ClReferralsTable';
import { ReferralFormModal } from '../components/ReferralFormModal';
import { useReferralsPage } from '../hooks/useReferralsPage';

export function ClReferralsPage() {
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
    type,
    setType,
    hasFilters,
    isMutating,
    crud,
    submit,
    logVisit,
  } = useReferralsPage();

  const { isAny } = useRole();
  const canEdit = isAny(CL_SALES_ROLES);

  return (
    <EntityListPage
      title="Referral partners"
      subtitle={`${total} physician, hospital, social-worker, and community channels feeding your pipeline`}
      addLabel="Add Source"
      onAdd={canEdit ? crud.openCreate : undefined}
      isLoading={isLoading}
      error={error}
      errorFallback="Failed to load referral sources"
      filters={
        <ReferralsFilters
          search={search}
          type={type}
          onSearch={setSearch}
          onType={setType}
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
      <ClReferralsTable
        items={rows}
        isMutating={isMutating}
        hasFilters={hasFilters}
        onEdit={crud.openEdit}
        onDelete={crud.confirmDelete}
        onLogVisit={logVisit}
        onAdd={canEdit ? crud.openCreate : undefined}
      />

      <ReferralFormModal
        open={crud.createOpen || crud.editing !== null}
        isSaving={crud.isSaving}
        editing={crud.editing}
        onClose={crud.editing ? crud.closeEdit : crud.closeCreate}
        onSubmit={submit}
      />
    </EntityListPage>
  );
}
