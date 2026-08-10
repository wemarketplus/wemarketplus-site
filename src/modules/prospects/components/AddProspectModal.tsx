import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { Button, Input, Label, Select, Textarea } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import { ProspectStage, ProspectUrgency } from '../types/prospectsTypes';
import {
  PROSPECT_STAGE_OPTIONS,
  PROSPECT_URGENCY_OPTIONS,
} from '../constants/prospectsConstants';
import { newProspectSchema, type NewProspectFormValues } from '../schema/prospectSchema';
import type { AddProspectModalProps } from '../types/prospectsTypes';

// Add Prospect modal — presentational. The page owns useAddProspect and passes
// the open/saving state plus the submit handler down.
export function AddProspectModal({ open, isSaving, onClose, onSubmit: submit }: AddProspectModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<NewProspectFormValues>({
    resolver: zodResolver(newProspectSchema),
    defaultValues: {
      patientName: '',
      facilityName: '',
      // MUST be a value that exists in PROSPECT_STAGE_OPTIONS (the canonical
      // ADMIT_STAGES). It used to default to the LEGACY `inquiry`, which is not
      // one of the options — so the <select> displayed "New Referral" while the
      // form state held `inquiry`, and an untouched form created a prospect at a
      // stage the Pipeline board has no column for. The card was saved and then
      // invisible.
      stage: ProspectStage.NewReferral,
      urgency: ProspectUrgency.Warm,
      referringPhysician: '',
      diagnosis: '',
      phone: '',
      notes: '',
    },
  });

  const close = () => {
    reset();
    onClose();
  };

  const onSubmit = async (values: NewProspectFormValues) => {
    const ok = await submit(values);
    if (ok) reset();
  };

  return (
    <Modal
      open={open}
      onClose={close}
      title="Add Prospect"
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={close} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={handleSubmit(onSubmit)} disabled={isSaving}>
            {isSaving ? 'Saving…' : 'Save Prospect'}
          </Button>
        </>
      }
    >
      <form onSubmit={handleSubmit(onSubmit)} className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <Label htmlFor="ap-name">Patient Name</Label>
          <Input id="ap-name" {...register('patientName')} />
          {errors.patientName && (
            <p className="mt-1 text-[12px] text-destructive">{errors.patientName.message}</p>
          )}
        </div>
        <div>
          <Label htmlFor="ap-facility">Facility</Label>
          <Input id="ap-facility" {...register('facilityName')} />
        </div>
        <div>
          <Label htmlFor="ap-physician">Referring physician</Label>
          <Input id="ap-physician" {...register('referringPhysician')} />
        </div>
        <div>
          <Label htmlFor="ap-stage">Stage</Label>
          <Select id="ap-stage" {...register('stage')}>
            {PROSPECT_STAGE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="ap-urgency">Urgency</Label>
          <Select id="ap-urgency" {...register('urgency')}>
            {PROSPECT_URGENCY_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="ap-diagnosis">Diagnosis</Label>
          <Input id="ap-diagnosis" {...register('diagnosis')} />
        </div>
        <div>
          <Label htmlFor="ap-phone">Phone</Label>
          <Input id="ap-phone" type="tel" {...register('phone')} />
        </div>
        <div className="sm:col-span-2">
          <Label htmlFor="ap-notes">Notes</Label>
          <Textarea id="ap-notes" {...register('notes')} />
        </div>
      </form>
    </Modal>
  );
}
