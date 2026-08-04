// Helpers for turning RHF form values into a DTO body the backend accepts.
// The backend runs `forbidNonWhitelisted` + rejects empty strings on optional
// fields, so blank optionals must be dropped rather than sent as "".

// Returns the trimmed string, or undefined when blank — for optional string DTO
// fields. Spread the result: `...opt('email', v.email)`.
export function opt(key: string, value: string | undefined | null): Record<string, string> {
  const trimmed = value?.trim();
  return trimmed ? { [key]: trimmed } : {};
}

// Same as `opt` but for numeric fields. NaN (empty number input) is dropped.
export function optNum(key: string, value: number | undefined | null): Record<string, number> {
  return value === undefined || value === null || Number.isNaN(value) ? {} : { [key]: value };
}

// --- Clearable optionals ---------------------------------------------------
// `opt`/`optNum` OMIT a blank value. In a PATCH an omitted key means "leave
// unchanged", so clearing a field in the edit form silently reverted it to the
// stored value — you could set a date but never unset one.
//
// These variants always send the key, using an explicit null for "blank". That
// round-trips end to end:
//   - class-validator's @IsOptional() skips a property whose value is null, so
//     @IsDateString/@IsUUID/@IsNumber never run on it (no 400).
//   - TypeORM's merge() applies null and skips only undefined, so save() really
//     does write NULL.
//
// ONLY use these on a column that is `nullable: true`. Sending null to a NOT
// NULL column (e.g. an auto-generated invoiceNumber/contractNumber) throws on
// update — keep `opt` for those so the key stays absent.

/** Trimmed string, or an explicit null when blank. For a nullable column. */
export function optOrNull(
  key: string,
  value: string | undefined | null,
): Record<string, string | null> {
  const trimmed = value?.trim();
  return { [key]: trimmed ? trimmed : null };
}

/** Numeric value, or an explicit null when blank/NaN. For a nullable column. */
export function optNumOrNull(
  key: string,
  value: number | undefined | null,
): Record<string, number | null> {
  const blank = value === undefined || value === null || Number.isNaN(value);
  return { [key]: blank ? null : value };
}
