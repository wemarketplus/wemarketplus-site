import type { ReactNode } from 'react';
import type {
  FieldValues,
  Path,
  UseFormRegister,
  UseFormSetValue,
  UseFormWatch,
  FieldErrors,
} from 'react-hook-form';

// --- Field descriptors -----------------------------------------------------
// A form modal is driven by a flat list of field descriptors. `register`
// wires the input to react-hook-form; `type` picks the primitive. This keeps a
// new module's create/edit form down to a schema plus a field array.

export type EntityFieldType =
  | 'text'
  /**
   * A PLACE. Renders the map picker (search, interactive map, drop a pin, use
   * my location) instead of a bare text box, and writes the chosen coordinates
   * into the two fields named by `latField` / `lngField`.
   *
   * Here rather than in each form because "where?" is asked by many of them —
   * an outreach visit, an appointment, a clock-in — and a location captured as
   * free text is a location nothing downstream can use: two people typing
   * "clinic" mean two different buildings.
   */
  | 'location'
  | 'email'
  | 'tel'
  | 'number'
  | 'date'
  /**
   * Date *and* time, for a column that stores a full timestamp. Use this rather
   * than 'date' whenever the backend column is a timestamp: a date input can
   * only express midnight, so it silently resets the time on every edit.
   * The form value is a zoneless local wall-clock string — convert it with
   * isoToLocalInput / localInputToIso from shared/utils/dateFormatter.
   */
  | 'datetime-local'
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
  | 'lookup'
  /**
   * Context the user may READ but not set: rendered as its label and a line of
   * text, with the display string supplied at render time through
   * EntityFormModalProps.readOnlyValues (keyed by field name, like `lookups`).
   *
   * Its purpose is a field whose value some roles choose and others only need to
   * see. The note form's Referral source is the case it exists for: a Marketer
   * picks one, a clinician is 403 on the list, and rendering the picker anyway
   * gave them a dropdown that could never contain anything. Any value already on
   * the record stays registered and is submitted untouched — this changes what is
   * rendered, not what is saved.
   */
  | 'readonly';

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
  /**
   * For `type: 'date'` / `'datetime-local'` only — the native input's `min`,
   * e.g. todayLocalDate() to grey out past dates in the picker itself. A
   * function so a `min` of "today" is read fresh each render rather than
   * frozen at module load (a form left open across midnight must not still
   * treat yesterday as selectable).
   */
  min?: string | (() => string);
  placeholder?: string;
  /**
   * For `type: 'location'` — the fields holding the picked coordinates. Both
   * required, because a coordinate is only meaningful as a pair, and they are
   * named rather than derived (`${name}Lat`) so a form can keep the column
   * names its table already uses: `gpsLat`/`gpsLng` on an outreach visit,
   * `locationLat`/`locationLng` on an appointment.
   *
   * Values are written as STRINGS, matching how these forms hold every other
   * value; the caller's mapper converts on submit, as it already does for miles
   * and dates.
   */
  latField?: Path<TValues>;
  lngField?: Path<TValues>;
  /**
   * For `type: 'lookup'` only — a DEPENDENT picker. Names the field whose value
   * decides which list this one offers, for a reference that is polymorphic:
   * pick the kind of record, then pick the record.
   *
   * Two things follow from it, both handled by EntityFormModal:
   *   - while the named field is blank this picker renders disabled and says
   *     which field to answer first (there is no list to offer yet);
   *   - changing the named field CLEARS this one, because a value chosen under
   *     the previous one came from a different list and saving it against the
   *     new one would point the record at nothing.
   *
   * The options themselves still arrive through `EntityFormModalProps.lookups`;
   * the caller swaps that list as the controlling field changes. Requires
   * `watch` + `setValue` on EntityFormModal.
   */
  dependsOn?: Path<TValues>;
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
  /**
   * RHF's `watch` and `setValue`. Needed ONLY when some field declares
   * `dependsOn`: `watch` tells a dependent picker whether its controlling field
   * has been answered, and `setValue` clears the picker when that answer
   * changes. Optional so every form without a dependent picker is unaffected.
   */
  watch?: UseFormWatch<TValues>;
  setValue?: UseFormSetValue<TValues>;
  onSubmit: () => void;
  onClose: () => void;
  /**
   * Options for `type: 'lookup'` fields, keyed by field name. A key that is
   * absent or still empty renders the picker disabled with a loading hint, so a
   * slow list never looks like an empty one.
   */
  lookups?: Readonly<Record<string, readonly EntitySelectOption[] | undefined>>;
  /**
   * Display strings for `type: 'readonly'` fields, keyed by field name.
   * `undefined` means still loading; `null` means "nothing on file", which is a
   * real answer and is shown as such rather than as a blank gap.
   */
  readOnlyValues?: Readonly<Record<string, string | null | undefined>>;
  // Optional slot rendered below the fields (e.g. a hint or extra control).
  footerNote?: ReactNode;
}
