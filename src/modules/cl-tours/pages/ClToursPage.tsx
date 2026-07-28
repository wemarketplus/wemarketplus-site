import { useRole, CL_SALES_ROLES } from '@/shared/rbac';
import { EntityListPage, EntityPagination } from '@/shared/ui/entity';
import { ToursFilters } from '../components/ToursFilters';
import { ToursTable } from '../components/ToursTable';
import { TourFormModal } from '../components/TourFormModal';
import { useToursPage } from '../hooks/useToursPage';

export function ClToursPage() {
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
    leadName,
    leadOptions,
    isMutating,
    crud,
    submit,
    changeStatus,
  } = useToursPage();

  const { isAny } = useRole();
  const canEdit = isAny(CL_SALES_ROLES);

  return (
    <EntityListPage
      title="Tour scheduler"
      subtitle={`${total} community tours`}
      addLabel="Book Tour"
      onAdd={canEdit ? crud.openCreate : undefined}
      isLoading={isLoading}
      error={error}
      errorFallback="Failed to load tours"
      filters={
        <ToursFilters
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
      <ToursTable
        tours={rows}
        isMutating={isMutating}
        hasFilters={hasFilters}
        leadName={leadName}
        onEdit={crud.openEdit}
        onDelete={crud.confirmDelete}
        onStatusChange={changeStatus}
        onAdd={canEdit ? crud.openCreate : undefined}
      />

      <TourFormModal
        open={crud.createOpen || crud.editing !== null}
        isSaving={crud.isSaving}
        editing={crud.editing}
        leadOptions={leadOptions}
        onClose={crud.editing ? crud.closeEdit : crud.closeCreate}
        onSubmit={submit}
      />
    </EntityListPage>
  );
}
