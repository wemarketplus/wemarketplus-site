import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { useProspectLookup, useReferralSourceLookup } from '@/shared/hooks';
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
  prospectId: '',
  referralSourceId: '',
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

  /**
   * The attribution pickers. Gated on `open` so a closed modal fetches neither
   * list, matching every other lookup in the app.
   */
  const lookups = {
    referralSourceId: useReferralSourceLookup(open),
    prospectId: useProspectLookup(open),
  };

  // DEPRECATED — NOT NEEDED, PENDING REMOVAL: the Application lookup that fed
  // the (now removed) applicationId field. The Grants domain was hidden from the
  // UI on 2026-08-06 per the product owner, so the form no longer fetches
  // GET /applications. To restore it, re-add the field to INVOICE_FIELDS and add
  //   applicationId: useApplicationLookup(open)
  // to the `lookups` object above.
  return (
    <EntityFormModal<InvoiceFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit invoice' : 'New invoice'}
      submitLabel={editing ? 'Save changes' : 'Create invoice'}
      fields={INVOICE_FIELDS}
      register={register}
      errors={errors}
      lookups={lookups}
      onSubmit={submit}
      onClose={close}
    />
  );
}
