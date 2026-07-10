import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { COMPANY_FIELDS, COMPANY_STATUS } from '../constants/companiesConstants';
import { companySchema, type CompanyFormValues } from '../schema/companySchema';
import { toCompanyFormValues } from '../utils/companiesUtils';
import type { CompanyRecord } from '../types/companiesTypes';

const EMPTY: CompanyFormValues = {
  companyName: '',
  status: COMPANY_STATUS.Prospect,
  companyType: '',
  industry: '',
  naicsCode: '',
  fein: '',
  employeeCountTotal: undefined,
  domain: '',
  website: '',
  primaryContactName: '',
  primaryContactEmail: '',
  primaryContactPhone: '',
  trainingNeeds: '',
  notes: '',
};

interface CompanyFormModalProps {
  open: boolean;
  isSaving: boolean;
  editing?: CompanyRecord | null;
  onClose: () => void;
  onSubmit: (values: CompanyFormValues) => Promise<boolean>;
}

// Owns the react-hook-form instance for create + edit and delegates rendering to
// the shared EntityFormModal. Mirror of ContactFormModal — the second reference.
export function CompanyFormModal({
  open,
  isSaving,
  editing,
  onClose,
  onSubmit,
}: CompanyFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<CompanyFormValues>({
    resolver: zodResolver(companySchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toCompanyFormValues(editing) : EMPTY);
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
    <EntityFormModal<CompanyFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit company' : 'Add company'}
      submitLabel={editing ? 'Save changes' : 'Save company'}
      fields={COMPANY_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
