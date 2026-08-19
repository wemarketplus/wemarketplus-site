import { useState } from 'react';
import { toast } from 'sonner';
import { useAppDispatch } from '@/app/hooks';
// Direct path, not the module barrel — same reason useAddProspect reaches for
// prospectsApi this way: the barrel also exports whole page trees this hook
// has no use for.
import { useCreateProspectMutation } from '@/modules/prospects/api/prospectsApi';
import { ProspectPipelineType } from '@/modules/prospects/types/prospectsTypes';
import type { CreateProspectRequest } from '@/modules/prospects/types/prospectsTypes';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { pipelineApi } from '../api/pipelineApi';
import { PIPELINE_TAGS } from '../constants/pipelineConstants';
import type { NewOpportunityFormValues } from '../schema/pipelineSchema';

// Orchestrates the Add-opportunity modal on the Pipeline board: open/close
// state plus the real POST /prospects mutation, fixed to the Outreach
// pipeline type. Reuses ProspectsService.create wholesale (a pipeline row IS
// a prospect) rather than a second creation endpoint.
export function useAddOpportunity() {
  const [open, setOpen] = useState(false);
  const dispatch = useAppDispatch();
  const [createProspect, { isLoading }] = useCreateProspectMutation();

  const submit = async (values: NewOpportunityFormValues): Promise<boolean> => {
    const body: CreateProspectRequest = {
      // The entity's `patientName` column is NOT NULL even for a non-patient
      // Outreach row (see Prospect entity) — the opportunity name doubles as
      // both `pipelineName` (what the Kanban card and this feature call it)
      // and `patientName` (what the column actually requires).
      patientName: values.name.trim(),
      pipelineName: values.name.trim(),
      pipelineType: ProspectPipelineType.Outreach,
      stage: values.stage,
      urgency: values.urgency,
      ...(values.facilityName?.trim() ? { facilityName: values.facilityName.trim() } : {}),
      ...(values.notes?.trim() ? { notes: values.notes.trim() } : {}),
    };

    try {
      await createProspect(body).unwrap();
      // createProspect's own invalidatesTags only reaches the Prospects list —
      // the Pipeline board is a separate API slice (GET /pipeline/board), so
      // without this the new card would not appear until a full reload.
      dispatch(
        pipelineApi.util.invalidateTags([{ type: PIPELINE_TAGS.Board, id: 'CURRENT' }]),
      );
      toast.success('Opportunity added');
      setOpen(false);
      return true;
    } catch (err) {
      toast.error(extractApiErrorMessage(err, 'Could not add opportunity. Please try again.'));
      return false;
    }
  };

  return {
    open,
    isSaving: isLoading,
    openModal: () => setOpen(true),
    close: () => setOpen(false),
    submit,
  };
}
