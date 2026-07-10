import type { ReactNode } from 'react';
import type {
  FieldValues,
  Path,
  UseFormRegister,
  FieldErrors,
} from 'react-hook-form';

// --- Field descriptors -----------------------------------------------------
// A form modal is driven by a flat list of field descriptors. `register`
// wires the input to react-hook-form; `type` picks the primitive. This keeps a
// new module's create/edit form down to a schema plus a field array.

export type EntityFieldType = 'text' | 'email' | 'tel' | 'number' | 'textarea' | 'select';

export interface EntitySelectOption {
  value: string;
  label: string;
}

export interface EntityField<TValues extends FieldValues> {
  name: Path<TValues>;
  label: string;
  type?: EntityFieldType;
  // Options are required for `type: 'select'`.
  options?: readonly EntitySelectOption[];
  placeholder?: string;
  // Span both columns of the 2-col grid (defaults to false = single column).
  full?: boolean;
}

export interface EntityFormModalProps<TValues extends FieldValues> {
  open: boolean;
  isSaving: boolean;
  // Title reflects create vs edit; the caller decides the copy.
  title: string;
  submitLabel: string;
  fields: ReadonlyArray<EntityField<TValues>>;
  register: UseFormRegister<TValues>;
  errors: FieldErrors<TValues>;
  onSubmit: () => void;
  onClose: () => void;
  // Optional slot rendered below the fields (e.g. a hint or extra control).
  footerNote?: ReactNode;
}
