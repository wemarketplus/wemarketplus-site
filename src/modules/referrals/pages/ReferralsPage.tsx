import { Plus } from 'lucide-react';
import { Button } from '@/shared/ui/core';
import { LogInteractionModal } from '@/modules/activity';
import { ScheduleVisitModal } from '@/modules/appointments';
import { ReferralsFilters } from '../components/ReferralsFilters';
import { ReferralsTable } from '../components/ReferralsTable';
import { AddReferralModal } from '../components/AddReferralModal';
import { ReferralSourceDrawer } from '../components/ReferralSourceDrawer';
import { useReferralsList } from '../hooks/useReferralsList';
import { useAddReferral } from '../hooks/useAddReferral';
import { useReferralSourceDetail } from '../hooks/useReferralSourceDetail';

export function ReferralsPage() {
  const { referrals, total, coldCount } = useReferralsList();
  const { open, isSaving, openModal, close, submit } = useAddReferral();
  const detail = useReferralSourceDetail();

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="font-display text-3xl text-foreground">
            Referral sources
          </h1>
          <p className="text-sm text-muted">
            {total} accounts
            {/* Surfaced in the header, not buried in the table, because the whole
                point of the cold rule is that it should be impossible to miss. */}
            {coldCount > 0 && (
              <span className="ml-2 text-destructive">
                · {coldCount} need a touch
              </span>
            )}
          </p>
        </div>
        <Button onClick={openModal}>
          <Plus className="h-4 w-4" /> Add source
        </Button>
      </header>

      <ReferralsFilters />
      <ReferralsTable items={referrals} onOpen={detail.open} />

      <AddReferralModal
        open={open}
        isSaving={isSaving}
        onClose={close}
        onSubmit={submit}
      />

      <ReferralSourceDrawer
        open={detail.isOpen}
        source={detail.source}
        notes={detail.notes}
        isLoading={detail.isLoading}
        isNotesLoading={detail.isNotesLoading}
        onClose={detail.close}
        onLogInteraction={detail.startLogging}
        onScheduleVisit={detail.startScheduling}
      />

      {detail.openId && (
        <>
          <LogInteractionModal
            open={detail.isLogging}
            isSaving={false}
            title={`Touch log — ${detail.source?.name ?? ''}`}
            target={{ referralSourceId: detail.openId }}
            onClose={detail.stopLogging}
            onSubmit={detail.logInteraction}
          />
          <ScheduleVisitModal
            open={detail.isScheduling}
            isSaving={false}
            target={{ companyId: detail.openId }}
            subjectName={detail.source?.name ?? ''}
            onClose={detail.stopScheduling}
            onSubmit={detail.schedule}
          />
        </>
      )}
    </div>
  );
}
