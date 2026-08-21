import { useRole, HL_CLINICAL_ROLES } from '@/shared/rbac';
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

  /**
   * WIDENED from `STAFF_ROLES`, which excludes Nurse and Caregiver — so the
   * "Schedule session" button was hidden from the two clinical personas even though
   * `POST /telehealth-sessions` and `PATCH :id` carry NO `@Roles` at all and would
   * have accepted them. A control the server permits and the UI never renders is
   * exactly what the nurse experienced as telehealth scheduling being a "Soon"
   * badge rather than a working feature.
   *
   * HL_CLINICAL_ROLES matches this route's own `allow` in the router, so the people
   * who can open the screen are the people who can act on it.
   *
   * Deletion is NOT gated here: TelehealthTable owns that gate (delete is
   * Manager-and-above server-side), and duplicating it would give the rule two
   * homes that could disagree.
   */
  const { isAny } = useRole();
  const canSchedule = isAny(HL_CLINICAL_ROLES);

  return (
    <EntityListPage
      title={title}
      subtitle={subtitle(total)}
      addLabel="Schedule session"
      onAdd={canSchedule ? crud.openCreate : undefined}
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
        onAdd={canSchedule ? crud.openCreate : undefined}
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
