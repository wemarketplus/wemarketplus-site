import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { CareLevel, LeadStatus, Urgency } from '@/shared/types';
import { Button, Input, Label, Select, Textarea } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import { CARE_LEVEL_LABELS, LEAD_STATUS_LABELS } from '../constants/leadsConstants';
import { newLeadSchema, type NewLeadFormValues } from '../schema/leadSchema';
import { useAddLead } from '../hooks/useAddLead';

// Add Lead modal — writes to the in-memory cl-leads slice so the new lead
// appears in the pipeline immediately (no backend; demo behaviour).
export function AddLeadModal() {
  const { open, close: dispatchClose, submit: dispatchSubmit } = useAddLead();

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<NewLeadFormValues>({
    resolver: zodResolver(newLeadSchema),
    defaultValues: {
      name: '',
      careType: CareLevel.AL,
      status: LeadStatus.Inquiry,
      urgency: Urgency.Warm,
      source: '',
      followUpDate: '',
      phone: '',
      email: '',
      notes: '',
    },
  });

  const close = () => {
    reset();
    dispatchClose();
  };

  const onSubmit = (v: NewLeadFormValues) => {
    dispatchSubmit(v);
    reset();
  };

  return (
    <Modal
      open={open}
      onClose={close}
      title="Add Lead"
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={close}>
            Cancel
          </Button>
          <Button onClick={handleSubmit(onSubmit)}>💾 Save Lead + Add to Pipeline</Button>
        </>
      }
    >
      <form onSubmit={handleSubmit(onSubmit)} className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <Label htmlFor="al-name">Prospect Name</Label>
          <Input id="al-name" {...register('name')} />
          {errors.name && <p className="mt-1 text-[12px] text-destructive">{errors.name.message}</p>}
        </div>
        <div>
          <Label htmlFor="al-care">Care Level</Label>
          <Select id="al-care" {...register('careType')}>
            {Object.values(CareLevel).map((c) => (
              <option key={c} value={c}>{CARE_LEVEL_LABELS[c]}</option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="al-status">Stage</Label>
          <Select id="al-status" {...register('status')}>
            {Object.values(LeadStatus).map((s) => (
              <option key={s} value={s}>{LEAD_STATUS_LABELS[s]}</option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="al-urgency">Urgency</Label>
          <Select id="al-urgency" {...register('urgency')}>
            <option value={Urgency.Hot}>Hot</option>
            <option value={Urgency.Warm}>Warm</option>
            <option value={Urgency.Cold}>Cold</option>
          </Select>
        </div>
        <div>
          <Label htmlFor="al-source">Source</Label>
          <Input id="al-source" {...register('source')} />
          {errors.source && <p className="mt-1 text-[12px] text-destructive">{errors.source.message}</p>}
        </div>
        <div>
          <Label htmlFor="al-phone">Phone</Label>
          <Input id="al-phone" type="tel" {...register('phone')} />
          {errors.phone && <p className="mt-1 text-[12px] text-destructive">{errors.phone.message}</p>}
        </div>
        <div>
          <Label htmlFor="al-email">Email</Label>
          <Input id="al-email" type="email" {...register('email')} />
          {errors.email && <p className="mt-1 text-[12px] text-destructive">{errors.email.message}</p>}
        </div>
        <div className="sm:col-span-2">
          <Label htmlFor="al-follow">Follow-up date</Label>
          <Input id="al-follow" type="date" {...register('followUpDate')} />
          {errors.followUpDate && (
            <p className="mt-1 text-[12px] text-destructive">{errors.followUpDate.message}</p>
          )}
        </div>
        <div className="sm:col-span-2">
          <Label htmlFor="al-notes">Notes</Label>
          <Textarea id="al-notes" {...register('notes')} />
        </div>
      </form>
    </Modal>
  );
}
