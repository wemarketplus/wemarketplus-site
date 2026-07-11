import { useRole, STAFF_ROLES } from '@/shared/rbac';
import { EntityListPage, EntityPagination } from '@/shared/ui/entity';
import { TelehealthTable } from '../components/TelehealthTable';
import { TelehealthFormModal } from '../components/TelehealthFormModal';
import { ClinicalFilters } from '../components/ClinicalFilters';
import { TELEHEALTH_STATUS_OPTIONS } from '../constants/clinicalTableConstants';
import { useTelehealthPage } from '../hooks/useTelehealthPage';

interface TelehealthPageProps {
  title: string;
  subtitle: (total: number) => string;
}

// /clinical/family and /clinical/messaging -> telehealth sessions list +
// create/edit/delete. Copy differs per route; the table + CRUD are identical.
export function TelehealthPage({ title, subtitle }: TelehealthPageProps) {
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
  } = useTelehealthPage();

  const { isAny } = useRole();
  const canEdit = isAny(STAFF_ROLES);

  return (
    <EntityListPage
      title={title}
      subtitle={subtitle(total)}
      addLabel="Schedule session"
      onAdd={canEdit ? crud.openCreate : undefined}
      isLoading={isLoading}
      error={error}
      errorFallback="Failed to load telehealth sessions"
      filters={
        <ClinicalFilters
          search={search}
          status={status}
          statusOptions={TELEHEALTH_STATUS_OPTIONS}
          searchPlaceholder="Search patient, provider…"
          searchLabel="Search telehealth sessions"
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
      <TelehealthTable
        sessions={rows}
        isMutating={isMutating}
        hasFilters={hasFilters}
        onEdit={crud.openEdit}
        onDelete={crud.confirmDelete}
        onAdd={canEdit ? crud.openCreate : undefined}
      />

      <TelehealthFormModal
        open={crud.createOpen || crud.editing !== null}
        isSaving={crud.isSaving}
        editing={crud.editing}
        onClose={crud.editing ? crud.closeEdit : crud.closeCreate}
        onSubmit={submit}
      />
    </EntityListPage>
  );
}
