import { PAGE_TITLE } from '@/shared/ui/core/typography';
import { Plus } from 'lucide-react';
import { useAppSelector } from '@/app/hooks';
import { STAFF_ROLES, useRole } from '@/shared/rbac';
import { Button } from '@/shared/ui/core';
import { ProspectsFilters } from '../components/ProspectsFilters';
import { ProspectsTable } from '../components/ProspectsTable';
import { AddProspectModal } from '../components/AddProspectModal';
import { LogInteractionModal } from '@/modules/activity';
import { ScheduleVisitModal } from '@/modules/appointments';
import { ProspectDrawer } from '../components/ProspectDrawer';
import { useProspectsList } from '../hooks/useProspectsList';
import { useAddProspect } from '../hooks/useAddProspect';
import { useProspectDetail } from '../hooks/useProspectDetail';
import { useProspectOwner } from '../hooks/useProspectOwner';
import { useTenantStaffOptions } from '@/modules/users';

export function ProspectsPage() {
  const { prospects, records, total, isUsingFixture } = useProspectsList();
  const { open, editing, isSaving, openModal, openEdit, close, submit, remove } = useAddProspect();
  const detail = useProspectDetail();

  /**
   * The Marketer column AND the drawer's clinical assignment picker are both
   * reassignment pickers over the same staff list, so the page loads the
   * tenant's assignable staff once and hands it to both rather than each
   * fetching its own.
   *
   * `/users/assignable` returns id and name only, which is what makes it readable
   * by a Marketer — the paginated `/users` list is Admin/Owner/Manager-only, and
   * reaching for it here would have left exactly the roles that own pipeline rows
   * with an empty picker. It is unfiltered by role for the same reason the
   * scheduling modals' own "Assign to" pickers are (ScheduleVisitModal,
   * ScheduleAppointmentModal): the projection carries no role column to filter on.
   */
  const { options: owners } = useTenantStaffOptions();
  const { assign, isSaving: isAssigning } = useProspectOwner();

  // Deletion is Admin/Owner/Manager-only on the backend (legacy: admin-only
  // delete) — mirror that gate on the action so a marketer never sees a button
  // that would just 403.
  const { isAny } = useRole();
  const canDelete = isAny(STAFF_ROLES);

  const editById = (id: string) => {
    const record = records.find((r) => r.id === id);
    if (record) openEdit(record);
  };
  const deleteById = (id: string) => {
    const record = records.find((r) => r.id === id);
    if (record) void remove(record);
  };

  // Distinguish a genuinely empty pipeline from a filtered-empty view so the
  // empty state shows the right message (get-started vs no-matches).
  const hasFilters = useAppSelector(
    (s) =>
      Boolean(s.prospects.search) ||
      s.prospects.statusFilter !== 'all' ||
      s.prospects.urgencyFilter !== 'all',
  );

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className={PAGE_TITLE}>Prospects</h1>
          <p className="text-sm text-muted">
            {total} prospects across your pipeline
            {isUsingFixture && (
              <span className="ml-2 rounded-pill bg-foreground/[0.04] px-2 py-0.5 text-[10px] uppercase tracking-label text-muted-soft">
                Preview data
              </span>
            )}
          </p>
        </div>
        <Button onClick={openModal}>
          <Plus className="h-4 w-4" /> Add prospect
        </Button>
      </header>

      <ProspectsFilters />
      <ProspectsTable
        prospects={prospects}
        onAdd={openModal}
        hasFilters={hasFilters}
        onOpen={detail.open}
        onEdit={editById}
        onDelete={canDelete ? deleteById : undefined}
        owners={owners}
        onOwnerChange={(id, userId) => void assign(id, userId)}
        isAssigning={isAssigning}
      />

      <AddProspectModal
        open={open}
        isSaving={isSaving}
        editing={editing}
        onClose={close}
        onSubmit={submit}
      />

      <ProspectDrawer
        open={detail.isOpen}
        prospect={detail.prospect}
        account={detail.account}
        notes={detail.notes}
        isLoading={detail.isLoading}
        isNotesLoading={detail.isNotesLoading}
        appointment={detail.appointment}
        isAppointmentLoading={detail.isAppointmentLoading}
        staffOptions={owners}
        onAssignRep={(userId) => void detail.assignRep(userId)}
        isAssigningRep={detail.isAssigningRep}
        onClose={detail.close}
        onAddNote={detail.startLogging}
        onScheduleVisit={detail.startScheduling}
      />

      {detail.openId && (
        <>
          <LogInteractionModal
            open={detail.isLogging}
            isSaving={false}
            title={`Add note — ${detail.prospect?.patientName ?? ''}`}
            target={{ prospectId: detail.openId }}
            // A note about a patient is where family-sensitive content lands;
            // an account note is not about a family at all.
            showFamilySensitive
            onClose={detail.stopLogging}
            onSubmit={detail.addNote}
          />
          <ScheduleVisitModal
            open={detail.isScheduling}
            isSaving={false}
            target={{
              pipelineId: detail.openId,
              contactId: detail.prospect?.primaryContactId ?? undefined,
            }}
            subjectName={detail.prospect?.patientName ?? ''}
            onClose={detail.stopScheduling}
            onSubmit={detail.schedule}
          />
        </>
      )}
    </div>
  );
}
