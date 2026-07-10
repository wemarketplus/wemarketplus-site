import { STAFF_ROLES, useRole } from '@/shared/rbac';
import { EntityListPage, EntityPagination } from '@/shared/ui/entity';
import { LocationsFilters } from '../components/LocationsFilters';
import { LocationsTable } from '../components/LocationsTable';
import { LocationFormModal } from '../components/LocationFormModal';
import { useLocations } from '../hooks/useLocations';

export function LocationsPage() {
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
    state,
    setState,
    isMutating,
    crud,
    submit,
  } = useLocations();

  // Create is staff-level; mirror the users-page convention of gating the Add
  // button (the backend allows any authenticated user to POST a location).
  const { isAny } = useRole();
  const canCreate = isAny(STAFF_ROLES);

  return (
    <>
      <EntityListPage
        title="Locations"
        subtitle={`${total} ${total === 1 ? 'location' : 'locations'} on file`}
        addLabel="Add location"
        onAdd={canCreate ? crud.openCreate : undefined}
        filters={
          <LocationsFilters
            search={search}
            onSearch={setSearch}
            status={status}
            onStatus={setStatus}
            state={state}
            onState={setState}
          />
        }
        isLoading={isLoading}
        error={error}
        errorFallback="Failed to load locations"
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
        <LocationsTable
          locations={rows}
          isMutating={isMutating}
          onEdit={crud.openEdit}
          onDelete={crud.confirmDelete}
        />
      </EntityListPage>

      <LocationFormModal
        open={crud.createOpen || crud.editing !== null}
        isSaving={crud.isSaving}
        editing={crud.editing}
        onClose={crud.editing ? crud.closeEdit : crud.closeCreate}
        onSubmit={submit}
      />
    </>
  );
}
