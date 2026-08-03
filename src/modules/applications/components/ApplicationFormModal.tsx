import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { useCompanyLookup, useFundingLookup } from '@/shared/hooks';
import { EntityFormModal } from '@/shared/ui/entity';
import {
  APPLICATION_CREATE_FIELDS,
  APPLICATION_EDIT_FIELDS,
} from '../constants/applicationsConstants';
import { applicationSchema, type ApplicationFormValues } from '../schema/applicationSchema';
import { toApplicationFormValues } from '../utils/applicationsUtils';
import type { ApplicationRecord } from '../types/applicationsTypes';

const EMPTY: ApplicationFormValues = {
  companyId: '',
  fundingOpportunityId: '',
  status: '',
  awardAmountRequested: undefined,
  awardAmountApproved: undefined,
  submissionDate: '',
  decisionDate: '',
  notes: '',
};

interface ApplicationFormModalProps {
  open: boolean;
  isSaving: boolean;
  editing?: ApplicationRecord | null;
  onClose: () => void;
  onSubmit: (values: ApplicationFormValues) => Promise<boolean>;
}

export function ApplicationFormModal({
  open,
  isSaving,
  editing,
  onClose,
  onSubmit,
}: ApplicationFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<ApplicationFormValues>({
    resolver: zodResolver(applicationSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toApplicationFormValues(editing) : EMPTY);
  }, [open, editing, reset]);

  const close = () => {
    reset(EMPTY);
    onClose();
  };

  const submit = handleSubmit(async (values) => {
    const ok = await onSubmit(values);
    if (ok) reset(EMPTY);
  });

  // Record pickers, fetched only while the form is open.
  const lookups = {
    companyId: useCompanyLookup(open),
    fundingOpportunityId: useFundingLookup(open),
  };
  return (
    <EntityFormModal<ApplicationFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit application' : 'Add application'}
      submitLabel={editing ? 'Save changes' : 'Save application'}
      fields={editing ? APPLICATION_EDIT_FIELDS : APPLICATION_CREATE_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      lookups={lookups}
      onClose={close}
    />
  );
}
