import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { CONTACT_FIELDS } from '../constants/contactsConstants';
import { useAttachableRecordLookup } from '../hooks/useAttachableRecordLookup';
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
    watch,
    setValue,
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

  // The `recordId` picker is dependent: the chosen record type decides which list
  // it offers, so it is watched here and the matching list fetched (only while the
  // form is open). EntityFormModal handles the rest of the pair's behaviour —
  // disabling the picker until a type is chosen, and clearing a record that was
  // picked under a different type.
  const recordType = watch('recordType');
  const lookups = { recordId: useAttachableRecordLookup(recordType, open) };

  return (
    <EntityFormModal<ContactFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit contact' : 'Add contact'}
      submitLabel={editing ? 'Save changes' : 'Save contact'}
      fields={CONTACT_FIELDS}
      register={register}
      errors={errors}
      watch={watch}
      setValue={setValue}
      onSubmit={submit}
      lookups={lookups}
      onClose={close}
    />
  );
}
