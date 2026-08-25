import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { Button, Input, Label, Select, Textarea } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import {
  OUTREACH_STAGE_OPTIONS,
  PROSPECT_URGENCY_OPTIONS,
} from '@/modules/prospects/constants/prospectsConstants';
import { ProspectStage, ProspectUrgency } from '@/modules/prospects/types/prospectsTypes';
import { newOpportunitySchema, type NewOpportunityFormValues } from '../schema/pipelineSchema';

interface AddOpportunityModalProps {
  open: boolean;
  isSaving: boolean;
  onClose: () => void;
  onSubmit: (values: NewOpportunityFormValues) => Promise<boolean>;
}

const EMPTY: NewOpportunityFormValues = {
  name: '',
  facilityName: '',
  stage: ProspectStage.Identified,
  urgency: ProspectUrgency.Warm,
  notes: '',
};

/**
 * Add Opportunity — the Pipeline board's only creation path. Unlike a
 * referral-to-admit prospect (Add Prospect, on the Prospects screen), an
 * Outreach-pipeline row is an account relationship, not a patient — there is
 * no other screen anywhere in the app that can start one, so the Kanban board
 * itself needs the "+".
 *
 * Posts to the SAME `POST /prospects` endpoint Add Prospect uses (a pipeline
 * row IS a prospect — see Prospect entity), fixed to `pipelineType: outreach`
 * so it lands in the Outreach board rather than duplicating a second
 * prospect-creation form.
 */
export function AddOpportunityModal({ open, isSaving, onClose, onSubmit: submit }: AddOpportunityModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<NewOpportunityFormValues>({
    resolver: zodResolver(newOpportunitySchema),
    defaultValues: EMPTY,
  });

  const close = () => {
    reset(EMPTY);
    onClose();
  };

  const onSubmit = async (values: NewOpportunityFormValues) => {
    const ok = await submit(values);
    if (ok) reset(EMPTY);
  };

  return (
    <Modal
      open={open}
      onClose={close}
      title="Add Opportunity"
      size="lg"
      footer={
        <>
          <Button variant="secondary" onClick={close} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={handleSubmit(onSubmit)} disabled={isSaving}>
            {isSaving ? 'Saving…' : 'Save Opportunity'}
          </Button>
        </>
      }
    >
      <form onSubmit={handleSubmit(onSubmit)} className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <Label htmlFor="ao-name">Opportunity name</Label>
          <Input id="ao-name" placeholder="Mercy General — home health partnership" {...register('name')} />
          {errors.name && <p className="mt-1 text-[12px] text-destructive">{errors.name.message}</p>}
        </div>
        <div>
          <Label htmlFor="ao-facility">Facility</Label>
          <Input id="ao-facility" {...register('facilityName')} />
        </div>
        <div>
          <Label htmlFor="ao-stage">Stage</Label>
          <Select id="ao-stage" {...register('stage')}>
            {OUTREACH_STAGE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        </div>
        <div className="sm:col-span-2">
          <Label htmlFor="ao-urgency">Urgency</Label>
          <Select id="ao-urgency" {...register('urgency')}>
            {PROSPECT_URGENCY_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        </div>
        <div className="sm:col-span-2">
          <Label htmlFor="ao-notes">Notes</Label>
          <Textarea id="ao-notes" {...register('notes')} />
        </div>
      </form>
    </Modal>
  );
}
