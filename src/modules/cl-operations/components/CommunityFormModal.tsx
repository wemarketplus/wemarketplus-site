import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { COMMUNITY_FIELDS } from '../constants/clOperationsConstants';
import { communitySchema, type CommunityFormValues } from '../schema/clOperationsSchema';
import { toCommunityFormValues } from '../utils/clOperationsMappers';
import type { ClCommunityRecord } from '../types/clOperationsApiTypes';

const EMPTY: CommunityFormValues = {
  name: '',
  city: '',
  state: '',
  phone: '',
  address: '',
  totalUnits: '',
};

interface Props {
  open: boolean;
  isSaving: boolean;
  editing?: ClCommunityRecord | null;
  onClose: () => void;
  onSubmit: (values: CommunityFormValues) => Promise<boolean>;
}

export function CommunityFormModal({ open, isSaving, editing, onClose, onSubmit }: Props) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<CommunityFormValues>({
    resolver: zodResolver(communitySchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toCommunityFormValues(editing) : EMPTY);
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
    <EntityFormModal<CommunityFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit community' : 'Add community'}
      submitLabel={editing ? 'Save changes' : 'Add community'}
      fields={COMMUNITY_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
