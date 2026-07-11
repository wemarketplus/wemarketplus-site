import { useRole, STAFF_ROLES } from '@/shared/rbac';
import { EntityListPage, EntityPagination } from '@/shared/ui/entity';
import { BedUnitsTable } from '../components/BedUnitsTable';
import { BedUnitFormModal } from '../components/BedUnitFormModal';
import { ClinicalFilters } from '../components/ClinicalFilters';
import { BED_UNIT_STATUS_OPTIONS } from '../constants/clinicalTableConstants';
import { useBedUnitsPage } from '../hooks/useBedUnitsPage';

// /clinical/admissions -> bed-units list + create/edit/delete.
export function AdmissionsPage() {
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
  } = useBedUnitsPage();

  const { isAny } = useRole();
  const canEdit = isAny(STAFF_ROLES);

  return (
    <EntityListPage
      title="Admissions and bed units"
      subtitle={`${total} bed units tracked across facilities`}
      addLabel="Add bed unit"
      onAdd={canEdit ? crud.openCreate : undefined}
      isLoading={isLoading}
      error={error}
      errorFallback="Failed to load bed units"
      filters={
        <ClinicalFilters
          search={search}
          status={status}
          statusOptions={BED_UNIT_STATUS_OPTIONS}
          searchPlaceholder="Search facility, patient…"
          searchLabel="Search bed units"
          statusAllLabel="All statuses"
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
      <BedUnitsTable
        units={rows}
        isMutating={isMutating}
        hasFilters={hasFilters}
        onEdit={crud.openEdit}
        onDelete={crud.confirmDelete}
        onAdd={canEdit ? crud.openCreate : undefined}
      />

      <BedUnitFormModal
        open={crud.createOpen || crud.editing !== null}
        isSaving={crud.isSaving}
        editing={crud.editing}
        onClose={crud.editing ? crud.closeEdit : crud.closeCreate}
        onSubmit={submit}
      />
    </EntityListPage>
  );
}
