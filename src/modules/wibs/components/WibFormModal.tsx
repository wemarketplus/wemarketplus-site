import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { WIB_FIELDS } from '../constants/wibsConstants';
import { wibSchema, type WibFormValues } from '../schema/wibSchema';
import { toWibFormValues } from '../utils/wibsUtils';
import type { WibRecord } from '../types/wibsTypes';

const EMPTY: WibFormValues = {
  wibName: '',
  sourceUrl: '',
  shortName: '',
  state: '',
  status: '',
  wibPhone: '',
  wibEmail: '',
  website: '',
  maxAwardPerEin: undefined,
  matchRequirementPct: undefined,
  wibType: '',
  nextSteps: '',
  blockers: '',
  notes: '',
};

interface WibFormModalProps {
  open: boolean;
  isSaving: boolean;
  editing?: WibRecord | null;
  onClose: () => void;
  onSubmit: (values: WibFormValues) => Promise<boolean>;
}

export function WibFormModal({ open, isSaving, editing, onClose, onSubmit }: WibFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<WibFormValues>({
    resolver: zodResolver(wibSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toWibFormValues(editing) : EMPTY);
  }, [open, editing, reset]);

  const close = () => {
    reset(EMPTY);
    onClose();
  };

  const submit = handleSubmit(async (values) => {
    const ok = await onSubmit(values);
    if (ok) reset(EMPTY);
  });

  return (
    <EntityFormModal<WibFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit WIB' : 'Add WIB'}
      submitLabel={editing ? 'Save changes' : 'Save WIB'}
      fields={WIB_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
