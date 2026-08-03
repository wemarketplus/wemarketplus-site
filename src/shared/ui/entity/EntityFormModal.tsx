import type { FieldValues } from 'react-hook-form';
import { get } from 'react-hook-form';
import { Button, Input, Label, Select, Textarea } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import type { EntityField, EntityFormModalProps } from './types';

// Presentational, field-driven create/edit modal. The caller owns the
// react-hook-form instance (schema, defaults, submit) and passes `register` +
// `errors` down, so this component stays generic across entities. Fields render
// into a 2-column grid; mark a field `full` to span both columns.
export function EntityFormModal<TValues extends FieldValues>({
  open,
  isSaving,
  title,
  submitLabel,
  fields,
  register,
  errors,
  onSubmit,
  onClose,
  lookups,
  footerNote,
}: EntityFormModalProps<TValues>) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={onSubmit} disabled={isSaving}>
            {isSaving ? 'Saving…' : submitLabel}
          </Button>
        </>
      }
    >
      <form onSubmit={onSubmit} className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        {fields.map((field) => (
          <EntityFieldControl
            key={field.name}
            field={field}
            register={register}
            errors={errors}
            lookupOptions={lookups?.[String(field.name)]}
          />
        ))}
        {footerNote && <div className="sm:col-span-2">{footerNote}</div>}
      </form>
    </Modal>
  );
}

function EntityFieldControl<TValues extends FieldValues>({
  field,
  register,
  errors,
  lookupOptions,
}: {
  field: EntityField<TValues>;
  register: EntityFormModalProps<TValues>['register'];
  errors: EntityFormModalProps<TValues>['errors'];
  lookupOptions?: readonly { value: string; label: string }[];
}) {
  const id = `ef-${String(field.name)}`;
  const type = field.type ?? 'text';
  // `get` handles nested paths safely; message may be undefined for valid fields.
  const error = get(errors, field.name) as { message?: string } | undefined;
  // number inputs need valueAsNumber so RHF gives zod a number, not a string.
  const reg = register(field.name, type === 'number' ? { valueAsNumber: true } : undefined);

  return (
    <div className={field.full ? 'sm:col-span-2' : undefined}>
      <Label htmlFor={id}>{field.label}</Label>
      {type === 'textarea' ? (
        <Textarea id={id} placeholder={field.placeholder} {...reg} />
      ) : type === 'lookup' ? (
        // A record reference. Options arrive from the caller's list query; until
        // they do, the picker is disabled and says so rather than looking empty.
        <Select id={id} {...reg} disabled={!lookupOptions}>
          <option value="">
            {lookupOptions
              ? (field.placeholder ?? 'Select…')
              : 'Loading…'}
          </option>
          {(lookupOptions ?? []).map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </Select>
      ) : type === 'select' ? (
        <Select id={id} {...reg}>
          {(field.options ?? []).map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </Select>
      ) : (
        <Input id={id} type={type} placeholder={field.placeholder} {...reg} />
      )}
      {error?.message && (
        <p className="mt-1 text-[12px] text-destructive">{error.message}</p>
      )}
    </div>
  );
}
