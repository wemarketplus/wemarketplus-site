import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { Button, Input, Label, Select, Textarea } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import { ReferralSourceType } from '../types/referralsTypes';
import { REFERRAL_ACCOUNT_STATUS_OPTIONS, REFERRAL_TYPE_OPTIONS } from '../constants/referralsConstants';
import { newReferralSchema, type NewReferralFormValues } from '../schema/referralSchema';
import { toReferralFormValues } from '../utils/referralsUtils';
import type { AddReferralModalProps } from '../types/referralsTypes';

const EMPTY: NewReferralFormValues = {
  name: '',
  type: ReferralSourceType.Hospital,
  status: '',
  contactName: '',
  phone: '',
  email: '',
  city: '',
  state: '',
  notes: '',
};

// Add/Edit Referral Source modal — presentational. The page owns
// useAddReferral. Doubles as the edit form: passing `editing` seeds the
// fields from that record (including its actual saved status) and switches
// the copy from Add to Edit.
export function AddReferralModal({ open, isSaving, editing, onClose, onSubmit: submit }: AddReferralModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<NewReferralFormValues>({
    resolver: zodResolver(newReferralSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toReferralFormValues(editing) : EMPTY);
  }, [open, editing, reset]);

  const close = () => {
    reset(EMPTY);
    onClose();
  };

  const onSubmit = async (values: NewReferralFormValues) => {
    const ok = await submit(values);
    if (ok) reset(EMPTY);
  };

  return (
    <Modal
      open={open}
      onClose={close}
      title={editing ? 'Edit Referral Source' : 'Add Referral Source'}
      size="lg"
      footer={
        <>
          <Button variant="secondary" onClick={close} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={handleSubmit(onSubmit)} disabled={isSaving}>
            {isSaving ? 'Saving…' : editing ? 'Save changes' : 'Save Source'}
          </Button>
        </>
      }
    >
      <form autoComplete="off" onSubmit={handleSubmit(onSubmit)} className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <Label htmlFor="ar-name">Source Name</Label>
          <Input id="ar-name" {...register('name')} />
          {errors.name && <p className="mt-1 text-[12px] text-destructive">{errors.name.message}</p>}
        </div>
        <div>
          <Label htmlFor="ar-type">Type</Label>
          <Select id="ar-type" {...register('type')}>
            {REFERRAL_TYPE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="ar-status">Status</Label>
          <Select id="ar-status" {...register('status')}>
            <option value="">Prospect (default)</option>
            {REFERRAL_ACCOUNT_STATUS_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="ar-contact">Contact name</Label>
          <Input id="ar-contact" {...register('contactName')} />
        </div>
        <div>
          <Label htmlFor="ar-phone">Phone</Label>
          <Input id="ar-phone" type="tel" {...register('phone')} />
        </div>
        <div>
          <Label htmlFor="ar-email">Email</Label>
          <Input id="ar-email" type="email" {...register('email')} />
          {errors.email && <p className="mt-1 text-[12px] text-destructive">{errors.email.message}</p>}
        </div>
        <div>
          <Label htmlFor="ar-city">City</Label>
          <Input id="ar-city" {...register('city')} />
        </div>
        <div>
          <Label htmlFor="ar-state">State</Label>
          <Input id="ar-state" {...register('state')} />
        </div>
        <div className="sm:col-span-2">
          <Label htmlFor="ar-notes">Notes</Label>
          <Textarea id="ar-notes" {...register('notes')} />
        </div>
      </form>
    </Modal>
  );
}
