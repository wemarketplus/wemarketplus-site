import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { CONTRACT_FIELDS } from '../constants/contractsConstants';
import { contractSchema, type ContractFormValues } from '../schema/contractSchema';
import { toContractFormValues } from '../utils/contractsUtils';
import type { ContractRecord } from '../types/contractsTypes';

const EMPTY: ContractFormValues = {
  companyName: '',
  contractType: '',
  value: undefined,
  status: 'draft',
  contractNumber: '',
  signedDate: '',
  expiryDate: '',
  notes: '',
};

interface ContractFormModalProps {
  open: boolean;
  isSaving: boolean;
  editing?: ContractRecord | null;
  onClose: () => void;
  onSubmit: (values: ContractFormValues) => Promise<boolean>;
}

// Owns the react-hook-form instance for create + edit and delegates rendering to
// the shared EntityFormModal. Resets from the edited record when it changes.
export function ContractFormModal({
  open,
  isSaving,
  editing,
  onClose,
  onSubmit,
}: ContractFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<ContractFormValues>({
    resolver: zodResolver(contractSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toContractFormValues(editing) : EMPTY);
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
    <EntityFormModal<ContractFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit contract' : 'New contract'}
      submitLabel={editing ? 'Save changes' : 'Create contract'}
      fields={CONTRACT_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
