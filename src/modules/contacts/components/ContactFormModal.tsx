import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { CONTACT_FIELDS } from '../constants/contactsConstants';
import { contactSchema, type ContactFormValues } from '../schema/contactSchema';
import { toContactFormValues } from '../utils/contactsUtils';
import type { ContactRecord } from '../types/contactsTypes';

const EMPTY: ContactFormValues = {
  name: '',
  title: '',
  email: '',
  phone: '',
  recordType: '',
  recordId: '',
  notes: '',
};

interface ContactFormModalProps {
  open: boolean;
  isSaving: boolean;
  // When set, the modal is in edit mode and seeds from this record.
  editing?: ContactRecord | null;
  onClose: () => void;
  onSubmit: (values: ContactFormValues) => Promise<boolean>;
}

// Owns the react-hook-form instance for create + edit and delegates rendering to
// the shared EntityFormModal. Resets from the edited record when it changes.
export function ContactFormModal({
  open,
  isSaving,
  editing,
  onClose,
  onSubmit,
}: ContactFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<ContactFormValues>({
    resolver: zodResolver(contactSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toContactFormValues(editing) : EMPTY);
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
    <EntityFormModal<ContactFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit contact' : 'Add contact'}
      submitLabel={editing ? 'Save changes' : 'Save contact'}
      fields={CONTACT_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
