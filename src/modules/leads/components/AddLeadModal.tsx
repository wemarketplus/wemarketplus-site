import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { Button, Input, Label, Select, Textarea } from '@/shared/ui/core';
import { useCompanyNameOptions } from '@/shared/hooks/useSharedLookups';
import { Modal } from '@/shared/ui/feedback';
import { LEAD_SOURCE_OPTIONS } from '../constants/leadsConstants';
import { newLeadSchema, type NewLeadFormValues } from '../schema/leadSchema';
import { LeadSourceType } from '../types/leadsTypes';

interface AddLeadModalProps {
  open: boolean;
  isSaving: boolean;
  onClose: () => void;
  // Returns true when the create succeeded, so the form can reset.
  onSubmit: (values: NewLeadFormValues) => Promise<boolean>;
}

export function AddLeadModal({
  open,
  isSaving,
  onClose,
  onSubmit: submit,
}: AddLeadModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<NewLeadFormValues>({
    resolver: zodResolver(newLeadSchema),
    defaultValues: {
      sourceType: LeadSourceType.Fax,
      sourceDetail: '',
      patientName: '',
      patientDob: '',
      diagnosisReason: '',
      referringPerson: '',
      referringOrg: '',
    },
  });

  // Referring organisations come from the Companies tab rather than being typed:
  // free text spawned a new spelling of the same facility on every intake, which
  // is what made referral-source reporting unusable. Gated on `open` so closing
  // the modal is the whole cost of not needing the list.
  const companyOptions = useCompanyNameOptions(open);

  const close = () => {
    reset();
    onClose();
  };

  const onSubmit = async (values: NewLeadFormValues) => {
    const ok = await submit(values);
    if (ok) reset();
  };

  return (
    <Modal
      open={open}
      onClose={close}
      title="Log inbound referral"
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={close} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={handleSubmit(onSubmit)} disabled={isSaving}>
            {isSaving ? 'Saving…' : 'Save lead'}
          </Button>
        </>
      }
    >
      <form
        onSubmit={handleSubmit(onSubmit)}
        className="grid grid-cols-1 gap-4 sm:grid-cols-2"
      >
        <div>
          <Label htmlFor="al-source">How did it arrive?</Label>
          <Select id="al-source" {...register('sourceType')}>
            {LEAD_SOURCE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="al-detail">Source detail</Label>
          <Input
            id="al-detail"
            placeholder="Fax line, form name, caller…"
            {...register('sourceDetail')}
          />
        </div>
        <div>
          <Label htmlFor="al-patient">Patient name</Label>
          <Input id="al-patient" {...register('patientName')} />
          {errors.patientName && (
            <p className="mt-1 text-[12px] text-destructive">
              {errors.patientName.message}
            </p>
          )}
        </div>
        <div>
          <Label htmlFor="al-dob">Patient DOB</Label>
          <Input id="al-dob" type="date" {...register('patientDob')} />
          {errors.patientDob && (
            <p className="mt-1 text-[12px] text-destructive">
              {errors.patientDob.message}
            </p>
          )}
        </div>
        <div>
          <Label htmlFor="al-person">Referring person</Label>
          <Input id="al-person" {...register('referringPerson')} />
        </div>
        <div>
          <Label htmlFor="al-org">Referring organisation</Label>
          <Select
            id="al-org"
            {...register('referringOrg')}
            disabled={!companyOptions}
          >
            <option value="">
              {!companyOptions
                ? 'Loading…'
                : companyOptions.length
                  ? 'Select a company…'
                  : 'No companies yet — add one in Companies'}
            </option>
            {(companyOptions ?? []).map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </Select>
        </div>
        <div className="sm:col-span-2">
          <Label htmlFor="al-reason">Diagnosis / reason</Label>
          <Textarea id="al-reason" {...register('diagnosisReason')} />
        </div>
      </form>
    </Modal>
  );
}
