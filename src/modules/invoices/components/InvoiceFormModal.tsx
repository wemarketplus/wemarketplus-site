import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { useApplicationLookup } from '@/shared/hooks';
import { EntityFormModal } from '@/shared/ui/entity';
import { INVOICE_FIELDS } from '../constants/invoicesConstants';
import { invoiceSchema, type InvoiceFormValues } from '../schema/invoiceSchema';
import { toInvoiceFormValues } from '../utils/invoicesUtils';
import type { InvoiceRecord } from '../types/invoicesTypes';

const EMPTY: InvoiceFormValues = {
  companyName: '',
  amount: 0,
  status: 'draft',
  invoiceNumber: '',
  feeModel: '',
  dueDate: '',
  applicationId: '',
  notes: '',
};

interface InvoiceFormModalProps {
  open: boolean;
  isSaving: boolean;
  editing?: InvoiceRecord | null;
  onClose: () => void;
  onSubmit: (values: InvoiceFormValues) => Promise<boolean>;
}

// Owns the react-hook-form instance for create + edit and delegates rendering to
// the shared EntityFormModal. Resets from the edited record when it changes.
export function InvoiceFormModal({
  open,
  isSaving,
  editing,
  onClose,
  onSubmit,
}: InvoiceFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<InvoiceFormValues>({
    resolver: zodResolver(invoiceSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toInvoiceFormValues(editing) : EMPTY);
  }, [open, editing, reset]);

  const close = () => {
    reset(EMPTY);
    onClose();
  };

  const submit = handleSubmit(async (values) => {
    const ok = await onSubmit(values);
    if (ok) reset(EMPTY);
  });

  const lookups = { applicationId: useApplicationLookup(open) };
  return (
    <EntityFormModal<InvoiceFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit invoice' : 'New invoice'}
      submitLabel={editing ? 'Save changes' : 'Create invoice'}
      fields={INVOICE_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      lookups={lookups}
      onClose={close}
    />
  );
}
