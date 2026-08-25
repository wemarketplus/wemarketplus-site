import { PAGE_TITLE } from '@/shared/ui/core/typography';
import { useState } from 'react';
import { Plus } from 'lucide-react';
import { Button } from '@/shared/ui/core';
import { AddLeadModal } from '../components/AddLeadModal';
import { DisqualifyLeadModal } from '../components/DisqualifyLeadModal';
import { LeadsFilters } from '../components/LeadsFilters';
import { LeadsTable } from '../components/LeadsTable';
import { useLeadActions } from '../hooks/useLeadActions';
import { useLeadsList } from '../hooks/useLeadsList';
import type { LeadDisqualifyReason, LeadRecord } from '../types/leadsTypes';

/**
 * Inbound referral intake — the pre-conversion queue. Converting a lead creates a
 * Contact, an account (referral source) and a pipeline row in one backend call.
 */
export function LeadsPage() {
  const {
    leads,
    total,
    isLoading,
    isError,
    search,
    statusFilter,
    sourceFilter,
    setSearch,
    setStatusFilter,
    setSourceFilter,
  } = useLeadsList();
  const {
    addOpen,
    openAdd,
    closeAdd,
    isCreating,
    isConverting,
    isDisqualifying,
    submitNew,
    convertLead,
    disqualifyLead,
  } = useLeadActions();
  const [pendingDisqualify, setPendingDisqualify] = useState<LeadRecord | null>(
    null,
  );

  const confirmDisqualify = async (reason: LeadDisqualifyReason) => {
    if (!pendingDisqualify) return;
    const ok = await disqualifyLead(pendingDisqualify.id, reason);
    if (ok) setPendingDisqualify(null);
  };

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className={PAGE_TITLE}>Inbound leads</h1>
          <p className="text-sm text-muted">
            {total} referrals in intake · convert to start a pipeline
          </p>
        </div>
        <Button onClick={openAdd}>
          <Plus className="h-4 w-4" /> Log referral
        </Button>
      </header>

      <LeadsFilters
        search={search}
        statusFilter={statusFilter}
        sourceFilter={sourceFilter}
        onSearch={setSearch}
        onStatus={setStatusFilter}
        onSource={setSourceFilter}
      />

      {isError && (
        <p className="rounded-md border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          Could not load inbound leads.
        </p>
      )}

      {isLoading ? (
        <p className="text-sm text-muted-soft">Loading leads…</p>
      ) : (
        <LeadsTable
          items={leads}
          isBusy={isConverting || isDisqualifying}
          onConvert={(lead) => void convertLead(lead.id)}
          onDisqualify={setPendingDisqualify}
        />
      )}

      <AddLeadModal
        open={addOpen}
        isSaving={isCreating}
        onClose={closeAdd}
        onSubmit={submitNew}
      />
      <DisqualifyLeadModal
        lead={pendingDisqualify}
        isSaving={isDisqualifying}
        onClose={() => setPendingDisqualify(null)}
        onConfirm={(reason) => void confirmDisqualify(reason)}
      />
    </div>
  );
}
