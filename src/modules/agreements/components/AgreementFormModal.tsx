import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { AGREEMENT_FIELDS } from '../constants/agreementsConstants';
import { agreementSchema, type AgreementFormValues } from '../schema/agreementSchema';
import { toAgreementFormValues } from '../utils/agreementsUtils';
import type { AgreementRecord } from '../types/agreementsTypes';

const EMPTY: AgreementFormValues = {
  agreementName: '',
  companyName: '',
  counterparty: '',
  agreementType: '',
  status: '',
  value: undefined,
  effectiveDate: '',
  expirationDate: '',
  notes: '',
};

interface AgreementFormModalProps {
  open: boolean;
  isSaving: boolean;
  editing?: AgreementRecord | null;
  onClose: () => void;
  onSubmit: (values: AgreementFormValues) => Promise<boolean>;
}

export function AgreementFormModal({ open, isSaving, editing, onClose, onSubmit }: AgreementFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<AgreementFormValues>({
    resolver: zodResolver(agreementSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toAgreementFormValues(editing) : EMPTY);
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
    <EntityFormModal<AgreementFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit agreement' : 'Add agreement'}
      submitLabel={editing ? 'Save changes' : 'Save agreement'}
      fields={AGREEMENT_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
