import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { Button, Input, Label, Select, Textarea } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import type { EntitySelectOption } from '@/shared/ui/entity';
import { APARTMENT_STATUS } from '../constants/clOperationsApiConstants';
import { APARTMENT_STATUS_OPTIONS } from '../constants/clOperationsConstants';
import { apartmentSchema, type ApartmentFormValues } from '../schema/clOperationsSchema';
import { toApartmentFormValues } from '../utils/clOperationsMappers';
import type { ClApartmentRecord } from '../types/clOperationsApiTypes';

const EMPTY: ApartmentFormValues = {
  communityId: '',
  unitNumber: '',
  unitType: '',
  status: APARTMENT_STATUS.Available,
  residentName: '',
  monthlyRate: '',
  notes: '',
};

interface Props {
  open: boolean;
  isSaving: boolean;
  editing?: ClApartmentRecord | null;
  communityOptions: readonly EntitySelectOption[];
  onClose: () => void;
  onSubmit: (values: ApartmentFormValues) => Promise<boolean>;
}

export function ApartmentFormModal({
  open,
  isSaving,
  editing,
  communityOptions,
  onClose,
  onSubmit,
}: Props) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<ApartmentFormValues>({
    resolver: zodResolver(apartmentSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    const seed = editing
      ? toApartmentFormValues(editing)
      : { ...EMPTY, communityId: communityOptions[0]?.value ?? '' };
    reset(seed);
  }, [open, editing, communityOptions, reset]);

  const close = () => {
    reset(EMPTY);
    onClose();
  };

  const submit = handleSubmit(async (values) => {
    const ok = await onSubmit(values);
    if (ok) reset(EMPTY);
  });

  return (
    <Modal
      open={open}
      onClose={close}
      title={editing ? 'Edit unit' : 'Add unit'}
      size="md"
      footer={
        <>
          <Button variant="secondary" onClick={close} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={isSaving}>
            {isSaving ? 'Saving…' : editing ? 'Save changes' : 'Add unit'}
          </Button>
        </>
      }
    >
      <form onSubmit={submit} className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <Label htmlFor="ap-community">Community</Label>
          <Select id="ap-community" {...register('communityId')}>
            <option value="">— Select community —</option>
            {communityOptions.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
          {errors.communityId && (
            <p className="mt-1 text-[12px] text-destructive">{errors.communityId.message}</p>
          )}
        </div>
        <div>
          <Label htmlFor="ap-unit">Unit number</Label>
          <Input id="ap-unit" placeholder="104" {...register('unitNumber')} />
          {errors.unitNumber && (
            <p className="mt-1 text-[12px] text-destructive">{errors.unitNumber.message}</p>
          )}
        </div>
        <div>
          <Label htmlFor="ap-type">Unit type</Label>
          <Input id="ap-type" placeholder="1BR / Studio" {...register('unitType')} />
        </div>
        <div>
          <Label htmlFor="ap-status">Status</Label>
          <Select id="ap-status" {...register('status')}>
            {APARTMENT_STATUS_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="ap-rate">Monthly rate</Label>
          <Input id="ap-rate" placeholder="4200" {...register('monthlyRate')} />
          {errors.monthlyRate && (
            <p className="mt-1 text-[12px] text-destructive">{errors.monthlyRate.message}</p>
          )}
        </div>
        <div className="sm:col-span-2">
          <Label htmlFor="ap-resident">Resident</Label>
          <Input id="ap-resident" placeholder="Earl Davis" {...register('residentName')} />
        </div>
        <div className="sm:col-span-2">
          <Label htmlFor="ap-notes">Notes</Label>
          <Textarea id="ap-notes" {...register('notes')} />
        </div>
      </form>
    </Modal>
  );
}
