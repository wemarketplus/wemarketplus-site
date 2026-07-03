import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { DOCUMENT_FIELDS } from '../constants/documentsConstants';
import { documentSchema, type DocumentFormValues } from '../schema/documentSchema';

const EMPTY: DocumentFormValues = {
  fileName: '',
  driveUrl: '',
  fileId: '',
  mimeType: '',
  documentType: '',
  notes: '',
};

interface DocumentFormModalProps {
  open: boolean;
  isSaving: boolean;
  onClose: () => void;
  onSubmit: (values: DocumentFormValues) => Promise<boolean>;
}

// Create-only modal — the documents domain has no update endpoint. Records
// metadata (name + driveUrl reference) for an existing file; no binary upload.
export function DocumentFormModal({ open, isSaving, onClose, onSubmit }: DocumentFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<DocumentFormValues>({
    resolver: zodResolver(documentSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (open) reset(EMPTY);
  }, [open, reset]);

  const close = () => {
    reset(EMPTY);
    onClose();
  };

  const submit = handleSubmit(async (values) => {
    const ok = await onSubmit(values);
    if (ok) reset(EMPTY);
  });

  return (
    <EntityFormModal<DocumentFormValues>
      open={open}
      isSaving={isSaving}
      title="Record document"
      submitLabel="Save document"
      fields={DOCUMENT_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
