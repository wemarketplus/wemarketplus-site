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

export type EntityFieldType =
  | 'text'
  | 'email'
  | 'tel'
  | 'number'
  | 'date'
  | 'textarea'
  | 'select'
  /**
   * A reference to another record, rendered as a picker whose options are loaded
   * at render time and passed via EntityFormModalProps.lookups (keyed by field
   * name). Use this for every foreign-key field.
   *
   * NEVER use a plain text input for a record reference: an end user has no way
   * to obtain a UUID, so a "paste the id" field is not a feature they can use.
   */
  | 'lookup';

export interface EntitySelectOption {
  value: string;
  label: string;
}

export interface EntityField<TValues extends FieldValues> {
  name: Path<TValues>;
  label: string;
  type?: EntityFieldType;
  // Options are required for `type: 'select'`. For `type: 'lookup'` they are
  // supplied at render time through EntityFormModalProps.lookups instead, since
  // they come from a server list the form cannot know about statically.
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
  /**
   * Options for `type: 'lookup'` fields, keyed by field name. A key that is
   * absent or still empty renders the picker disabled with a loading hint, so a
   * slow list never looks like an empty one.
   */
  lookups?: Readonly<Record<string, readonly EntitySelectOption[] | undefined>>;
  // Optional slot rendered below the fields (e.g. a hint or extra control).
  footerNote?: ReactNode;
}
