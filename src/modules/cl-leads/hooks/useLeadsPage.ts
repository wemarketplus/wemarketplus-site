import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useDebounce } from '@/shared/hooks';
import { usePaginatedList, useEntityCrud } from '@/shared/ui/entity';
import {
  useListClLeadsQuery,
  useCreateClLeadMutation,
  useUpdateClLeadMutation,
  useDeleteClLeadMutation,
} from '../api/leadsApi';
import { CL_LEAD_STAGE, type ClLostReason } from '../constants/clLeadApiConstants';
import { CL_LEADS_PAGE_SIZE } from '../constants/leadsConstants';
import { leadName, toCreateLead, toUpdateLead } from '../utils/leadsUtils';
import type { LeadFormValues } from '../schema/leadSchema';
import type { ClLeadRecord } from '../types/clLeadApiTypes';

// The single hook LeadsPage consumes: the paginated /cl/leads query with
// server-side search + stage + urgency filters (each fires a fresh request over
// the whole dataset, not just the current page), plus the shared create/edit/
// delete orchestration wired to the real mutations. Mirrors the canonical
// modules/contacts template — no in-memory slice.
export function useLeadsPage() {
  /**
   * Filters SEED FROM THE QUERY STRING so a caller can link to a narrowed
   * pipeline: the dashboard's "Hot leads" tile is the guide's "check the Hot
   * Leads list first", and without this it could only drop the reader into the
   * full book to re-apply the filter by hand.
   *
   * Read once as the initial state rather than kept in sync with the URL — the
   * selects are the source of truth once the screen is open, and rewriting the
   * URL on every keystroke would put filter churn in the back-button history.
   */
  const [searchParams] = useSearchParams();
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [stage, setStage] = useState(() => searchParams.get('stage') ?? '');
  const [urgency, setUrgency] = useState(() => searchParams.get('urgency') ?? '');
  const debouncedSearch = useDebounce(search, 300);

  // Any filter change resets to page 1 (the filtered result set is a new list).
  useEffect(() => setPage(1), [debouncedSearch, stage, urgency]);

  const query = useListClLeadsQuery({
    page,
    limit: CL_LEADS_PAGE_SIZE,
    search: debouncedSearch.trim(),
    stage,
    urgency,
  });
  const list = usePaginatedList<ClLeadRecord>(query, {
    pageSize: CL_LEADS_PAGE_SIZE,
  });

  const [createLead, createState] = useCreateClLeadMutation();
  const [updateLead, updateState] = useUpdateClLeadMutation();
  const [deleteLead, deleteState] = useDeleteClLeadMutation();

  const crud = useEntityCrud<
    ClLeadRecord,
    ReturnType<typeof toCreateLead>,
    ReturnType<typeof toUpdateLead>
  >({
    noun: 'lead',
    create: createLead,
    update: updateLead,
    remove: deleteLead,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: leadName,
  });

  const submit = (values: LeadFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateLead(values))
      : crud.submitCreate(toCreateLead(values));

  /**
   * The lead awaiting a loss reason, or null.
   *
   * `Lost` is the one stage that cannot commit straight from the table: the server
   * requires a reason, so asking for it first is what keeps the control from
   * firing a request that is guaranteed to fail. Every other stage is unchanged.
   */
  const [pendingLoss, setPendingLoss] = useState<ClLeadRecord | null>(null);

  // Inline stage change from the pipeline table — a targeted PATCH, except for
  // `Lost`, which routes through the reason prompt below.
  const changeStage = (lead: ClLeadRecord, stageValue: string) => {
    if (stageValue === CL_LEAD_STAGE.Lost && !lead.lostReason) {
      // Only when the lead does NOT already carry a reason. Re-selecting `Lost` on
      // a lead that is already lost with a recorded reason is a no-op the server
      // accepts as-is, and re-prompting for an answer already on file would read
      // as the app having forgotten it.
      setPendingLoss(lead);
      return undefined;
    }
    return crud.submitUpdate(lead.id, {
      stage: stageValue as ClLeadRecord['stage'],
    });
  };

  /** Commits the loss once the prompt has a reason. */
  const confirmLoss = async (
    lostReason: ClLostReason,
    lostReasonDetail: string | null,
  ) => {
    if (!pendingLoss) return;
    await crud.submitUpdate(pendingLoss.id, {
      stage: CL_LEAD_STAGE.Lost,
      lostReason,
      // Sent as null rather than omitted for a non-`other` reason, so switching a
      // lead from "Other — family postponed" to "Price" does not leave the old
      // note attached to the new reason.
      lostReasonDetail,
    });
    setPendingLoss(null);
  };

  const hasFilters = Boolean(debouncedSearch.trim() || stage || urgency);

  return {
    ...list,
    page,
    prevPage: () => setPage((p) => Math.max(1, p - 1)),
    nextPage: () => setPage((p) => Math.min(list.lastPage, p + 1)),
    search,
    setSearch,
    stage,
    setStage,
    urgency,
    setUrgency,
    hasFilters,
    isMutating: createState.isLoading || updateState.isLoading || deleteState.isLoading,
    crud,
    submit,
    changeStage,
    pendingLoss,
    cancelLoss: () => setPendingLoss(null),
    confirmLoss,
  };
}
