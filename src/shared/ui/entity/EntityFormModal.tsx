import { useEffect } from 'react';
import type { FieldValues, Path, PathValue } from 'react-hook-form';
import { get } from 'react-hook-form';
import {
  LocationField,
  toLocationValue,
  type LocationValue,
} from '@/modules/geocoding';
import { Button, DatePicker, Input, Label, Select, Textarea } from '@/shared/ui/core';
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
  watch,
  setValue,
  onSubmit,
  onClose,
  lookups,
  readOnlyValues,
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
          {/*
            `secondary`, NOT `ghost` — the app's standard quiet button, so Cancel
            wears a visible hairline + raised wash instead of borderless muted
            type on white, which reads as disabled next to the filled submit.
            Same report, same fix as ConfirmDialog; see the note there.
          */}
          <Button variant="secondary" onClick={onClose} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={onSubmit} disabled={isSaving}>
            {isSaving ? 'Saving…' : submitLabel}
          </Button>
        </>
      }
    >
      {/*
        Form-level `off` as well as per-field: some browsers consult only the
        form when deciding whether to run profile autofill at all, and a field
        that opts in with a real token still wins over this (the spec resolves
        the nearest declaration). Belt and braces, because the failure mode is
        silent — a value changes and nothing in the app did it.
      */}
      <form
        onSubmit={onSubmit}
        autoComplete="off"
        className="grid grid-cols-1 gap-4 sm:grid-cols-2"
      >
        {fields.map((field) => (
          <EntityFieldControl
            key={field.name}
            field={field}
            // The fields that name THIS one in `dependsOn`. Their current value
            // was chosen against this field's old value, so it is stale the
            // moment this one changes.
            dependents={fields.filter((f) => f.dependsOn === field.name)}
            // The label of the field THIS one depends on, so a picker that is
            // not usable yet can name what to answer first.
            dependsOnLabel={fields.find((f) => f.name === field.dependsOn)?.label}
            register={register}
            errors={errors}
            watch={watch}
            setValue={setValue}
            lookupOptions={lookups?.[String(field.name)]}
            readOnlyValue={readOnlyValues?.[String(field.name)]}
          />
        ))}
        {footerNote && <div className="sm:col-span-2">{footerNote}</div>}
      </form>
    </Modal>
  );
}

function EntityFieldControl<TValues extends FieldValues>({
  field,
  dependents,
  dependsOnLabel,
  register,
  errors,
  watch,
  setValue,
  lookupOptions,
  readOnlyValue,
}: {
  field: EntityField<TValues>;
  dependents: ReadonlyArray<EntityField<TValues>>;
  dependsOnLabel?: string;
  register: EntityFormModalProps<TValues>['register'];
  errors: EntityFormModalProps<TValues>['errors'];
  watch?: EntityFormModalProps<TValues>['watch'];
  setValue?: EntityFormModalProps<TValues>['setValue'];
  lookupOptions?: readonly { value: string; label: string }[];
  readOnlyValue?: string | null;
}) {
  const id = `ef-${String(field.name)}`;
  const type = field.type ?? 'text';
  // `get` handles nested paths safely; message may be undefined for valid fields.
  const error = get(errors, field.name) as { message?: string } | undefined;
  // number inputs need valueAsNumber so RHF gives zod a number, not a string.
  const reg = register(field.name, type === 'number' ? { valueAsNumber: true } : undefined);

  // A dependent picker (`dependsOn`) has nothing to offer until its controlling
  // field is answered — which list to read is exactly what that answer decides.
  const isBlocked = Boolean(field.dependsOn) && !watch?.(field.dependsOn!);

  // Restoring a SEEDED reference. `reset` writes the stored value into the DOM
  // <select>, but a native select silently drops a value that has no matching
  // <option> yet — and the options arrive from a request that, for a dependent
  // picker, cannot even begin until `reset` has supplied the controlling value.
  // Without re-applying it the edit form opens having quietly forgotten which
  // record the row was attached to. Re-apply once the option actually exists.
  const selected = type === 'lookup' ? watch?.(field.name) : undefined;
  useEffect(() => {
    if (!selected || !setValue) return;
    if (!lookupOptions?.some((o) => o.value === selected)) return;
    setValue(field.name, selected);
  }, [selected, lookupOptions, field.name, setValue]);

  // Changing a field that others depend on invalidates their values. Done on the
  // change EVENT rather than in an effect on the value: seeding an edit form goes
  // through `reset`, which fires no event, so a stored pair survives untouched.
  const control = {
    ...(dependents.length
      ? {
          ...reg,
          onChange: (event: Parameters<typeof reg.onChange>[0]) => {
            const result = reg.onChange(event);
            for (const dependent of dependents) {
              // A dependent field is a picker, so blank is the empty option.
              setValue?.(dependent.name, '' as PathValue<TValues, Path<TValues>>);
            }
            return result;
          },
        }
      : reg),
    // Carried on the CONTROL, not the label: `aria-required` is what tells
    // assistive tech the field is mandatory, and it lands on every visible
    // branch below (input, select, textarea, date) because they all spread
    // `control`. The `readonly` branch spreads `reg` into a hidden input
    // instead and is deliberately excluded — a value the user cannot set is
    // not a field they can be required to fill.
    ...(field.required ? { 'aria-required': true } : {}),
    /**
     * Browser autofill is OFF unless the field opts in. Same reasoning as
     * `aria-required` for the placement: it has to reach every branch below, so
     * it rides on `control` rather than being repeated five times.
     *
     * An entity form describes another RECORD, not the person typing, so the
     * browser's profile has nothing right to offer — and left unlabelled it does
     * not stay quiet, it guesses. A form carrying a name + phone + email reads to
     * Chrome as an address form, at which point its profile heuristics are
     * applied to every control in the form including the `<select>`s, which is
     * how the Leads pipeline's Stage changed on its own during an autofill. See
     * EntityField.autoComplete.
     */
    autoComplete: field.autoComplete ?? 'off',
  };

  // A place picker owns its own label and writes THREE values (the name and the
  // two coordinates), so it returns before the shared label/branch below rather
  // than pretending to be a one-value input.
  if (type === 'location' && field.latField && field.lngField) {
    const asText = (path: Path<TValues>): string =>
      (watch?.(path) as string | undefined) ?? '';
    const write = (path: Path<TValues>, value: string) =>
      setValue?.(path, value as PathValue<TValues, Path<TValues>>, {
        shouldDirty: true,
      });
    const lat = Number(asText(field.latField));
    const lng = Number(asText(field.lngField));
    const value = toLocationValue(
      asText(field.name),
      asText(field.latField) && Number.isFinite(lat) ? lat : null,
      asText(field.lngField) && Number.isFinite(lng) ? lng : null,
    );
    const onChange = (next: LocationValue) => {
      write(field.name, next.label);
      // Written as a pair or cleared as a pair — half a point is not a location,
      // and the API rejects one anyway.
      write(field.latField!, next.coords ? String(next.coords.lat) : '');
      write(field.lngField!, next.coords ? String(next.coords.lng) : '');
    };
    return (
      <div className={field.full ? 'sm:col-span-2' : undefined}>
        {/* Registered but hidden: the form still owns these values, so a save
            carries the coordinates even though no visible input holds them. */}
        <input type="hidden" {...register(field.latField)} />
        <input type="hidden" {...register(field.lngField)} />
        <LocationField
          id={id}
          label={field.label}
          value={value}
          onChange={onChange}
          placeholder={field.placeholder}
        />
        {error?.message && (
          <p className="mt-1 text-[12px] text-destructive">{error.message}</p>
        )}
      </div>
    );
  }

  return (
    <div className={field.full ? 'sm:col-span-2' : undefined}>
      {/* The `*` now lives on <Label> itself, so the hand-rolled modals that
          build their own field rows mark required fields the same way this one
          does instead of having no way to. Rationale for the marker's tone and
          its `aria-hidden` is recorded there. */}
      <Label htmlFor={id} required={field.required}>
        {field.label}
      </Label>
      {type === 'readonly' ? (
        // Context, not an input. The value is still registered (hidden) so an
        // existing reference on the record survives a save by a role that only
        // reads it — dropping the input must not drop the data.
        <>
          <input type="hidden" {...reg} />
          <p
            id={id}
            className="pt-1.5 text-sm text-foreground [word-break:break-word]"
          >
            {readOnlyValue === undefined ? (
              <span className="text-muted-soft">Loading…</span>
            ) : (
              (readOnlyValue ?? (
                <span className="text-muted-soft">Not on file</span>
              ))
            )}
          </p>
        </>
      ) : type === 'textarea' ? (
        <Textarea id={id} placeholder={field.placeholder} {...control} />
      ) : type === 'lookup' ? (
        // A record reference. Options arrive from the caller's list query; until
        // they do, the picker is disabled and says so rather than looking empty.
        <Select id={id} {...control} disabled={isBlocked || !lookupOptions}>
          <option value="">
            {isBlocked
              ? `Select a ${(dependsOnLabel ?? 'type').toLowerCase()} first`
              : lookupOptions
                ? (field.placeholder ?? 'Select…')
                : 'Loading…'}
          </option>
          {(isBlocked ? [] : (lookupOptions ?? [])).map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </Select>
      ) : type === 'select' ? (
        <Select id={id} {...control}>
          {(field.options ?? []).map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </Select>
      ) : type === 'date' ? (
        // The shared calendar control rather than `<input type="date">`, whose
        // icon Chrome draws as a grey glyph, Safari omits, and Firefox draws
        // differently again. The value stays a `yyyy-MM-dd` string, so `control`
        // (the react-hook-form registration) spreads in unchanged and every
        // schema and DTO downstream is untouched — see DatePicker.
        <DatePicker
          id={id}
          min={
            field.min
              ? typeof field.min === 'function'
                ? field.min()
                : field.min
              : undefined
          }
          {...control}
        />
      ) : (
        <Input
          id={id}
          type={type}
          placeholder={field.placeholder}
          min={
            type === 'datetime-local' && field.min
              ? typeof field.min === 'function'
                ? field.min()
                : field.min
              : undefined
          }
          {...control}
        />
      )}
      {error?.message && (
        <p className="mt-1 text-[12px] text-destructive">{error.message}</p>
      )}
    </div>
  );
}
