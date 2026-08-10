import { Plus } from 'lucide-react';
import { useAppSelector } from '@/app/hooks';
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

export function ProspectsPage() {
  const { prospects, total, isUsingFixture } = useProspectsList();
  const { open, isSaving, openModal, close, submit } = useAddProspect();
  const detail = useProspectDetail();

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
          <h1 className="font-display text-3xl text-foreground">Prospects</h1>
          <p className="text-sm text-muted">
            {total} prospects across your pipeline
            {isUsingFixture && (
              <span className="ml-2 rounded-pill bg-foreground/[0.04] px-2 py-0.5 text-[10px] uppercase tracking-[0.1em] text-muted-soft">
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
      />

      <AddProspectModal open={open} isSaving={isSaving} onClose={close} onSubmit={submit} />

      <ProspectDrawer
        open={detail.isOpen}
        prospect={detail.prospect}
        account={detail.account}
        notes={detail.notes}
        isLoading={detail.isLoading}
        isNotesLoading={detail.isNotesLoading}
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
