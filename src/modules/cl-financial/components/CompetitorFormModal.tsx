import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { COMPETITOR_FIELDS } from '../constants/clFinancialConstants';
import { competitorSchema, type CompetitorFormValues } from '../schema/clFinancialSchema';
import { toCompetitorFormValues } from '../utils/clFinancialMappers';
import type { ClCompetitorRecord } from '../types/clFinancialApiTypes';

const EMPTY: CompetitorFormValues = {
  name: '',
  city: '',
  distanceMiles: '',
  rateIl: '',
  rateAl: '',
  rateMc: '',
  occupancyPct: '',
  notes: '',
};

interface Props {
  open: boolean;
  isSaving: boolean;
  editing?: ClCompetitorRecord | null;
  onClose: () => void;
  onSubmit: (values: CompetitorFormValues) => Promise<boolean>;
}

export function CompetitorFormModal({ open, isSaving, editing, onClose, onSubmit }: Props) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<CompetitorFormValues>({
    resolver: zodResolver(competitorSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toCompetitorFormValues(editing) : EMPTY);
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
    <EntityFormModal<CompetitorFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit competitor' : 'Add competitor'}
      submitLabel={editing ? 'Save changes' : 'Add competitor'}
      fields={COMPETITOR_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
