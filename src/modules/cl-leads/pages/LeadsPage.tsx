import { useRole, CL_SALES_ROLES } from '@/shared/rbac';
import { EntityListPage, EntityPagination } from '@/shared/ui/entity';
import { LeadsFilters } from '../components/LeadsFilters';
import { LeadsTable } from '../components/LeadsTable';
import { LeadFormModal } from '../components/LeadFormModal';
import { LostReasonModal } from '../components/LostReasonModal';
import { useLeadsPage } from '../hooks/useLeadsPage';
import { leadName } from '../utils/leadsUtils';

export function LeadsPage() {
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
    stage,
    setStage,
    urgency,
    setUrgency,
    hasFilters,
    isMutating,
    crud,
    submit,
    changeStage,
    pendingLoss,
    cancelLoss,
    confirmLoss,
  } = useLeadsPage();

  // Add/edit is a staff action; read-only roles see the list without the CTA.
  const { isAny } = useRole();
  const canEdit = isAny(CL_SALES_ROLES);

  return (
    <EntityListPage
      title="Lead pipeline"
      subtitle={`${total} leads across the senior-living pipeline`}
      addLabel="Add Lead"
      onAdd={canEdit ? crud.openCreate : undefined}
      isLoading={isLoading}
      error={error}
      errorFallback="Failed to load leads"
      filters={
        <LeadsFilters
          search={search}
          stage={stage}
          urgency={urgency}
          onSearch={setSearch}
          onStage={setStage}
          onUrgency={setUrgency}
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
      <LeadsTable
        leads={rows}
        isMutating={isMutating}
        hasFilters={hasFilters}
        onEdit={crud.openEdit}
        onDelete={crud.confirmDelete}
        onStageChange={changeStage}
        onAdd={canEdit ? crud.openCreate : undefined}
      />

      <LeadFormModal
        open={crud.createOpen || crud.editing !== null}
        isSaving={crud.isSaving}
        editing={crud.editing}
        onClose={crud.editing ? crud.closeEdit : crud.closeCreate}
        onSubmit={submit}
      />

      {/*
        Mounted only while a loss is pending, so the dialog's own state resets
        between leads — a reason typed for one lead must not be sitting in the box
        when the next one is marked lost.
      */}
      {pendingLoss && (
        <LostReasonModal
          leadName={leadName(pendingLoss)}
          isSaving={crud.isSaving}
          onCancel={cancelLoss}
          onConfirm={confirmLoss}
        />
      )}
    </EntityListPage>
  );
}
