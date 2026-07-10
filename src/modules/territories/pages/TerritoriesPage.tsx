import { useRole, Role } from '@/shared/rbac';
import { EntityListPage, EntityPagination } from '@/shared/ui/entity';
import { TerritoriesFilters } from '../components/TerritoriesFilters';
import { TerritoriesTable } from '../components/TerritoriesTable';
import { TerritoryFormModal } from '../components/TerritoryFormModal';
import { useTerritories } from '../hooks/useTerritories';

// Create/update/delete are Admin/Owner/Manager on the backend; gate the Add button
// (and the row actions, in the table) to the same roles.
const MANAGE_ROLES: readonly Role[] = [Role.SuperAdmin, Role.Admin, Role.Owner, Role.Manager];

export function TerritoriesPage() {
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
    isMutating,
    crud,
    submit,
  } = useTerritories();

  const { isAny } = useRole();
  const canManage = isAny(MANAGE_ROLES);

  return (
    <>
      <EntityListPage
        title="Territories"
        subtitle={`${total} ${total === 1 ? 'territory' : 'territories'} defined`}
        addLabel="Add territory"
        onAdd={canManage ? crud.openCreate : undefined}
        filters={<TerritoriesFilters search={search} onSearch={setSearch} />}
        isLoading={isLoading}
        error={error}
        errorFallback="Failed to load territories"
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
        <TerritoriesTable
          territories={rows}
          isMutating={isMutating}
          onEdit={crud.openEdit}
          onDelete={crud.confirmDelete}
        />
      </EntityListPage>

      <TerritoryFormModal
        open={crud.createOpen || crud.editing !== null}
        isSaving={crud.isSaving}
        editing={crud.editing}
        onClose={crud.editing ? crud.closeEdit : crud.closeCreate}
        onSubmit={submit}
      />
    </>
  );
}
